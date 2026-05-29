using VerifyBlind.Core.Crypto;
using VerifyBlind.Core.Models;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Local (software-backed) IKmsService implementation.
/// Uses a single HMAC key for all ID derivations and country-specific RSA keys for ticket signing.
/// Domain separation is achieved via distinct input formats (e.g. TCKN_Person_id vs sodHash_Card_id).
/// </summary>
public class LocalKmsService : IKmsService
{
    private static readonly byte[] HmacKey = SHA256.HashData("verifyblind-hmac-user-dev"u8);

    // --- Country-Specific Ticket Keys (k_ticket_ISO) ---
    // Hardcoded for known countries. Unknown countries auto-generate a new RSA-2048 key at runtime (Seçenek A).
    private readonly Dictionary<string, (string Priv, string Pub)> _countryKeys = new()
    {
        { "TUR", (
            "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"
        )},
        { "DEFAULT", (
            "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"
        )}
    };

    // Runtime-generated keys for unknown countries (in-memory, lost on restart — dev only)
    private readonly ConcurrentDictionary<string, (string Priv, string Pub)> _runtimeCountryKeys = new();

    public LocalKmsService()
    {
        Console.WriteLine("[LocalKmsService] Initialized with single HMAC key + country ticket keys.");
    }

    public Task<string> ComputeHmacAsync(string data)
    {
        using var hmac = new HMACSHA256(HmacKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Task.FromResult(Convert.ToBase64String(hash));
    }

    public Task<string> SignTicketAsync(TicketPayload ticket)
    {
        var keys = GetOrCreateCountryKeys(ticket.CountryIsoCode);
        var json = JsonSerializer.Serialize(ticket);
        return Task.FromResult(CryptoUtils.SignData(json, keys.Priv));
    }

    public Task<bool> VerifyTicketSignatureAsync(SignedTicket signedTicket)
    {
        var keys = GetOrCreateCountryKeys(signedTicket.Payload.CountryIsoCode);
        var json = JsonSerializer.Serialize(signedTicket.Payload);
        return Task.FromResult(CryptoUtils.VerifySignature(json, signedTicket.Signature, keys.Pub));
    }

    private (string Priv, string Pub) GetOrCreateCountryKeys(string countryCode)
    {
        if (_countryKeys.TryGetValue(countryCode, out var known))
            return known;

        return _runtimeCountryKeys.GetOrAdd(countryCode, code =>
        {
            using var rsa = RSA.Create(2048);
            var priv = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            var pub  = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            Console.WriteLine($"[LocalKmsService] Auto-created runtime RSA key for country: {code}");
            return (priv, pub);
        });
    }
}
