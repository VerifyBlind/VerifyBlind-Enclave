using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

public class AwsKmsService : IKmsService, IDisposable
{
    private readonly AmazonKeyManagementServiceClient _client;
    private readonly IConfiguration _configuration;

    public AwsKmsService(IConfiguration configuration)
    {
        _configuration = configuration;

        var kmsConfig = new AmazonKeyManagementServiceConfig
        {
            RegionEndpoint = RegionEndpoint.GetBySystemName(
                configuration["KMS:Region"] ?? "eu-central-1")
        };

        var endpoint = configuration["KMS:Endpoint"];
        if (!string.IsNullOrEmpty(endpoint))
        {
            var region = configuration["KMS:Region"] ?? "eu-central-1";
            kmsConfig.ServiceURL = endpoint;
            // When ServiceURL is set, SDK loses region context for request signing
            kmsConfig.AuthenticationRegion = region;
            // vsock-proxy: bağlantı 127.0.0.1'e gider ama TLS uçtan uca enclave↔KMS'tir
            // (proxy yalnızca şifreli byte taşır). Sertifikayı gerçek KMS host'una karşı
            // doğrula → parent ele geçirilip proxy kötü endpoint'e yönlendirilse bile MITM olmaz.
            kmsConfig.HttpClientFactory = new VsockProxyHttpClientFactory($"kms.{region}.amazonaws.com");
        }

        _client = new AmazonKeyManagementServiceClient(kmsConfig);
    }

    /// <summary>
    /// vsock-proxy üzerinden KMS'e bağlanırken TLS doğrulamasını DOĞRU yapar:
    /// bağlantı 127.0.0.1'e gittiği için hostname uyuşmazlığı BEKLENİR ve tolere edilir,
    /// ancak (1) sertifika zinciri güvenilir bir köke çıkmalı, (2) sertifika gerçekten
    /// kms.&lt;region&gt;.amazonaws.com için olmalıdır. Böylece parent ele geçirilip vsock-proxy
    /// kötü bir endpoint'e yönlendirilse dahi, sahte sunucu geçerli KMS sertifikası sunamaz
    /// → TLS handshake başarısız → TCKN/ticket sızmaz (yalnızca DoS mümkün).
    /// Tek bir SocketsHttpHandler ile connection pooling sağlar.
    /// </summary>
    private sealed class VsockProxyHttpClientFactory : Amazon.Runtime.HttpClientFactory
    {
        private readonly HttpClient _cached;

        public VsockProxyHttpClientFactory(string expectedKmsHost)
        {
            var handler = new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = (_, certificate, _, sslPolicyErrors) =>
                    {
                        // 127.0.0.1'e bağlandığımız için YALNIZCA hostname-mismatch beklenir; onu tolere et.
                        // Zincir hatası (güvenilmeyen kök) veya sertifika yokluğu = olası MITM → REDDET.
                        const SslPolicyErrors tolerated = SslPolicyErrors.RemoteCertificateNameMismatch;
                        if ((sslPolicyErrors & ~tolerated) != SslPolicyErrors.None)
                            return false;
                        // Sunulan sertifika gerçekten KMS host'u için mi? (RFC 6125 SAN eşleşmesi)
                        return certificate is X509Certificate2 cert2 && cert2.MatchesHostname(expectedKmsHost);
                    }
                },
                PooledConnectionLifetime = TimeSpan.FromMinutes(10),
                MaxConnectionsPerServer = 20,
                EnableMultipleHttp2Connections = true
            };
            _cached = new HttpClient(handler);
        }

        public override HttpClient CreateHttpClient(IClientConfig clientConfig)
        {
            return _cached;
        }
    }

    public async Task<string> ComputeHmacAsync(string data)
    {
        var keyAlias = _configuration["KMS:HmacKeyAlias"]
            ?? "alias/verifyblind-hmac-userid";

        var request = new GenerateMacRequest
        {
            KeyId = keyAlias,
            MacAlgorithm = MacAlgorithmSpec.HMAC_SHA_256,
            Message = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(data))
        };

        var response = await _client.GenerateMacAsync(request);
        return Convert.ToBase64String(response.Mac.ToArray());
    }

    public async Task<byte[]> DecryptWithAttestationAsync(byte[] ciphertext, byte[] attestationDocument)
    {
        // EncryptionContext (AAD) — bootstrap'taki kms:Encrypt ile BİREBİR aynı olmalı (§4.1 bütünlük).
        var request = new DecryptRequest
        {
            CiphertextBlob = new MemoryStream(ciphertext),
            EncryptionContext = new Dictionary<string, string>
            {
                ["purpose"] = "ticket-mac",
                ["app"] = "verifyblind"
            },
            Recipient = new RecipientInfo
            {
                KeyEncryptionAlgorithm = KeyEncryptionMechanism.RSAES_OAEP_SHA_256,
                AttestationDocument = new MemoryStream(attestationDocument)
            }
        };

        var response = await _client.DecryptAsync(request);
        // Recipient set olduğunda Plaintext BOŞ döner; sır CiphertextForRecipient (CMS) içindedir.
        if (response.CiphertextForRecipient == null)
            throw new InvalidOperationException("KMS Decrypt CiphertextForRecipient döndürmedi (Recipient/attestation desteği?).");
        return response.CiphertextForRecipient.ToArray();
    }

    public void Dispose() => _client.Dispose();
}