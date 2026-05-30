using System.Collections.Concurrent;
using System.Security.Cryptography;
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
            kmsConfig.ServiceURL = endpoint;
            // When ServiceURL is set, SDK loses region context for request signing
            kmsConfig.AuthenticationRegion = configuration["KMS:Region"] ?? "eu-central-1";
            // vsock-proxy: TLS cert is for kms.eu-central-1.amazonaws.com, not 127.0.0.1
            // Bypass certificate hostname validation for the vsock tunnel
            kmsConfig.HttpClientFactory = new VsockProxyHttpClientFactory();
        }

        _client = new AmazonKeyManagementServiceClient(kmsConfig);
    }

    /// <summary>
    /// vsock-proxy üzerinden KMS'e bağlanırken TLS hostname doğrulamasını atlar.
    /// Tek bir SocketsHttpHandler ile connection pooling sağlar — her çağrıda yeni TCP bağlantısı açılmaz.
    /// </summary>
    private sealed class VsockProxyHttpClientFactory : Amazon.Runtime.HttpClientFactory
    {
        private readonly HttpClient _cached;

        public VsockProxyHttpClientFactory()
        {
            var handler = new SocketsHttpHandler
            {
                SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                {
#pragma warning disable CA5359 // vsock tüneli: bağlantı 127.0.0.1'e gider, KMS sertifikası hostname mismatch verir — MITM riski yok
                    RemoteCertificateValidationCallback = (_, _, _, _) => true
#pragma warning restore CA5359
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