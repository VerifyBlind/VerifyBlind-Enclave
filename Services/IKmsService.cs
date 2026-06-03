using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

public interface IKmsService
{
    Task<string> ComputeHmacAsync(string data);

    /// <summary>
    /// Attestation-bound KMS Decrypt (Nitro Recipient). <paramref name="ciphertext"/> wrapping CMK ile
    /// sarılmış blob'tur; <paramref name="attestationDocument"/> enclave'in ephemeral public key'ini
    /// (public_key alanında) taşıyan TAZE attestation belgesidir. KMS, key policy'deki PCR0 koşulunu
    /// doğrular ve plaintext'i enclave'in ephemeral public key'ine RSAES_OAEP_SHA_256 ile şifreleyip
    /// CiphertextForRecipient (CMS/PKCS7) olarak döner. Dönen CMS, enclave'in ephemeral private key'iyle
    /// (<see cref="IEnclaveKeyService.DecryptCmsForRecipient"/>) açılır.
    /// Yalnız TICKET_AUTH_MODE=mac + KMS_MODE=aws + gerçek Nitro donanımında kullanılır.
    /// </summary>
    Task<byte[]> DecryptWithAttestationAsync(byte[] ciphertext, byte[] attestationDocument);
}
