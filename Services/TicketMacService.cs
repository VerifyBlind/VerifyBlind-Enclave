using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Ticket'ları enclave-içi SİMETRİK HMAC-MAC ile imzalar (register) ve doğrular (login).
/// KMS Sign/Verify'in yerini alır (Ticket Forgery fix — TICKET_FORGERY_FIX_PLAN.md).
/// İmzalayan=doğrulayan=enclave olduğu için asimetrik gerekmez.
/// </summary>
public interface ITicketMacService
{
    /// <summary>
    /// Ticket-MAC secret'ını RAM'e yükler (boot başına 1 kez, idempotent + thread-safe).
    /// AWS modunda: <paramref name="wrappedBlobB64"/> attestation-bound Decrypt + CMS açma ile çözülür.
    /// Dev modunda: sabit dev secret (blob yok sayılır).
    /// </summary>
    Task EnsureSecretLoadedAsync(string? wrappedBlobB64);

    string ComputeMac(TicketPayload payload);
    bool VerifyMac(SignedTicket signedTicket);
}

public class TicketMacService : ITicketMacService
{
    private readonly IKmsService _kms;
    private readonly IEnclaveKeyService _keys;
    private readonly bool _awsMode;

    // Domain separation: MAC girdisinin amaç-dışı yeniden kullanımını engeller.
    private static readonly byte[] Label = Encoding.UTF8.GetBytes("vb-ticket-v1\n");

    private byte[]? _secret;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public TicketMacService(IKmsService kms, IEnclaveKeyService keys, IConfiguration config)
    {
        _kms = kms;
        _keys = keys;
        _awsMode = string.Equals(config["KMS_MODE"], "aws", StringComparison.OrdinalIgnoreCase);
    }

    public async Task EnsureSecretLoadedAsync(string? wrappedBlobB64)
    {
        if (_secret != null) return;
        await _gate.WaitAsync();
        try
        {
            if (_secret != null) return;

            if (_awsMode)
            {
                if (string.IsNullOrEmpty(wrappedBlobB64))
                    throw new InvalidOperationException(
                        "ticket_secret_wrapped boş — relay system_settings'ten blob iletmedi (TICKET_AUTH_MODE=mac).");

                var ciphertext = Convert.FromBase64String(wrappedBlobB64);
                var attDoc = _keys.GetAttestationDocumentForRecipient();
                var cms = await _kms.DecryptWithAttestationAsync(ciphertext, attDoc);
                var secret = _keys.DecryptCmsForRecipient(cms);

                if (secret == null || secret.Length < 16)
                    throw new InvalidOperationException(
                        $"Çözülen ticket-MAC secret beklenenden kısa ({secret?.Length ?? 0} bayt).");

                _secret = secret;
                Console.WriteLine($"[TicketMacService] Ticket-MAC secret attestation-bound Decrypt ile yüklendi ({secret.Length} bayt).");
            }
            else
            {
                // DEV: gerçek KMS/Nitro yok → sabit dev secret. PROD'da (KMS_MODE=aws) bu yola ASLA girilmez.
                _secret = SHA256.HashData(Encoding.UTF8.GetBytes("verifyblind-ticket-mac-dev-secret-v1"));
                Console.WriteLine("[TicketMacService] DEV ticket-MAC secret kullanılıyor (KMS_MODE!=aws).");
            }
        }
        finally { _gate.Release(); }
    }

    public string ComputeMac(TicketPayload payload)
    {
        var secret = _secret ?? throw new InvalidOperationException(
            "Ticket-MAC secret yüklenmedi (EnsureSecretLoadedAsync çağrılmadı).");
        var json = JsonSerializer.SerializeToUtf8Bytes(payload);
        return Convert.ToBase64String(ComputeHmac(secret, json));
    }

    public bool VerifyMac(SignedTicket signedTicket)
    {
        var secret = _secret ?? throw new InvalidOperationException(
            "Ticket-MAC secret yüklenmedi (EnsureSecretLoadedAsync çağrılmadı).");

        byte[] provided;
        try { provided = Convert.FromBase64String(signedTicket.Signature); }
        catch { return false; }

        var json = JsonSerializer.SerializeToUtf8Bytes(signedTicket.Payload);
        var expected = ComputeHmac(secret, json);
        return CryptographicOperations.FixedTimeEquals(expected, provided);
    }

    private static byte[] ComputeHmac(byte[] secret, byte[] message)
    {
        using var hmac = new HMACSHA256(secret);
        hmac.TransformBlock(Label, 0, Label.Length, null, 0);
        hmac.TransformFinalBlock(message, 0, message.Length);
        return hmac.Hash!;
    }
}
