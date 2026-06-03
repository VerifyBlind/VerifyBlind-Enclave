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
    private readonly ConcurrentDictionary<string, string> _countryKeyCache = new();

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

    public async Task<string> SignTicketAsync(TicketPayload ticket)
    {
        var countryCode = ticket.CountryIsoCode ?? "DEFAULT";
        var keyArn = await ResolveOrCreateCountryKeyAsync(countryCode);

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(ticket);
        var digest = SHA256.HashData(jsonBytes);

        var request = new SignRequest
        {
            KeyId = keyArn,
            SigningAlgorithm = SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
            MessageType = MessageType.DIGEST,
            Message = new MemoryStream(digest)
        };

        var response = await _client.SignAsync(request);
        return Convert.ToBase64String(response.Signature.ToArray());
    }

    public async Task<bool> VerifyTicketSignatureAsync(SignedTicket signedTicket)
    {
        var countryCode = signedTicket.Payload.CountryIsoCode ?? "DEFAULT";
        var keyArn = await ResolveOrCreateCountryKeyAsync(countryCode);

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(signedTicket.Payload);
        var digest = SHA256.HashData(jsonBytes);

        var signatureBytes = Convert.FromBase64String(signedTicket.Signature);

        var request = new VerifyRequest
        {
            KeyId = keyArn,
            SigningAlgorithm = SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
            MessageType = MessageType.DIGEST,
            Message = new MemoryStream(digest),
            Signature = new MemoryStream(signatureBytes)
        };

        try
        {
            var response = await _client.VerifyAsync(request);
            return response.SignatureValid;
        }
        catch (KMSInvalidSignatureException)
        {
            return false;
        }
    }

    private async Task<string> ResolveOrCreateCountryKeyAsync(string countryCode)
    {
        if (_countryKeyCache.TryGetValue(countryCode, out var cachedArn))
            return cachedArn;

        var aliasPattern = _configuration["KMS:TicketKeyAliasPattern"] ?? "alias/verifyblind-ticket-{0}";
        var alias = string.Format(aliasPattern, countryCode);

        try
        {
            var describeResponse = await _client.DescribeKeyAsync(new DescribeKeyRequest { KeyId = alias });
            var arn = describeResponse.KeyMetadata.Arn;
            _countryKeyCache[countryCode] = arn;
            return arn;
        }
        catch (NotFoundException)
        {
            var createResponse = await _client.CreateKeyAsync(new CreateKeyRequest
            {
                KeySpec = KeySpec.RSA_2048,
                KeyUsage = KeyUsageType.SIGN_VERIFY,
                Description = $"VerifyBlind ticket signing - {countryCode}"
            });

            var newArn = createResponse.KeyMetadata.Arn;

            await _client.CreateAliasAsync(new CreateAliasRequest
            {
                AliasName = alias,
                TargetKeyId = newArn
            });

            _countryKeyCache[countryCode] = newArn;
            return newArn;
        }
    }

    public void Dispose() => _client.Dispose();
}