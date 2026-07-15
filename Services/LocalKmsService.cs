using System.Security.Cryptography;
using System.Text;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Local (software-backed) IKmsService implementation — yalnız dev.
/// Tek HMAC key ile ID türetme (person_id / card_id / user_id); domain separation girdi formatlarıyla.
/// Ticket imzalama enclave-içi MAC'e taşındı (Ticket Forgery fix) → burada ticket Sign/Verify YOK.
/// DecryptWithAttestationAsync dev'de desteklenmez (gerçek KMS/Nitro gerekir).
/// </summary>
public class LocalKmsService : IKmsService
{
    private static readonly byte[] HmacKey = SHA256.HashData("verifyblind-hmac-user-dev"u8);

    public LocalKmsService()
    {
        Console.WriteLine("[LocalKmsService] Initialized (HMAC-only; ticket imzalama enclave MAC'inde).");
    }

    public Task<string> ComputeHmacAsync(string data)
    {
        using var hmac = new HMACSHA256(HmacKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Task.FromResult(Convert.ToBase64String(hash));
    }

    public Task<byte[]> DecryptWithAttestationAsync(byte[] ciphertext, byte[] attestationDocument)
    {
        // Dev modunda gerçek KMS/Nitro yok → attestation-bound decrypt anlamsız.
        // TicketMacService local modda sabit dev secret kullanır, bu yolu ÇAĞIRMAZ.
        throw new NotSupportedException(
            "DecryptWithAttestationAsync local KMS modunda desteklenmez (KMS_MODE=aws gerekir).");
    }
}
