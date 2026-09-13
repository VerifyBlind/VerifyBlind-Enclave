namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Local (software-backed) IKmsService implementation — yalnız dev.
///
/// <para>Eskiden burada tek bir HMAC anahtarıyla ID türetme (person_id / card_id / user_id)
/// vardı. O yol KALDIRILDI: takma ad türetme artık <see cref="IdentityHmacService"/> içinde,
/// enclave'e attestation-bound Decrypt ile gelen bir sırla yapılıyor. Sebep — KMS'in attestation
/// parametresi MAC işlemlerinde desteklenmediği için <c>kms:GenerateMac</c> izni EC2 rolünde
/// kalmak zorundaydı ve sunucuya erişen herkes bir TCKN'nin user_id'sini hesaplatabiliyordu.</para>
///
/// <para>Geriye yalnız <see cref="DecryptWithAttestationAsync"/> kalıyor ve dev'de desteklenmiyor
/// (gerçek KMS + Nitro donanımı gerekir). Dev modunda hem <see cref="TicketMacService"/> hem
/// <see cref="IdentityHmacService"/> sabit dev secret kullanır ve bu yolu ÇAĞIRMAZ.</para>
/// </summary>
public class LocalKmsService : IKmsService
{
    public LocalKmsService()
    {
        Console.WriteLine("[LocalKmsService] Initialized (dev — attestation-bound Decrypt desteklenmez).");
    }

    public Task<byte[]> DecryptWithAttestationAsync(byte[] ciphertext, byte[] attestationDocument, string purpose)
    {
        // Dev modunda gerçek KMS/Nitro yok → attestation-bound decrypt anlamsız.
        throw new NotSupportedException(
            $"DecryptWithAttestationAsync local KMS modunda desteklenmez (purpose={purpose}, KMS_MODE=aws gerekir).");
    }
}
