using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Wrapping CMK ile sarılmış sırların KMS EncryptionContext'teki <c>purpose</c> değerleri.
///
/// <para>Tek bir wrapping CMK (<c>alias/verifyblind-ticket-mac-wrap</c>) birden fazla sırrı
/// taşır; ayrımı EncryptionContext sağlar. KMS bu bağlamı AAD olarak bağladığı için bir amaç
/// için sarılmış blob, başka bir amacın bağlamıyla <b>açılamaz</b> — kriptografik ayrım.</para>
///
/// <para><b>Neden ikinci bir CMK değil:</b> her CMK ayrı bir key policy demek ve o policy her
/// enclave deploy'unda PCR0 rotasyonuyla güncellenmek zorunda. İki politikanın zamanla ayrışması
/// tek kişilik bir operasyonda gerçek ve tekrarlayan bir arıza kaynağı. CMK'nın işi zaten
/// "sırrı yalnız attested enclave'e ver"; ikinci sır için ikinci politika taşımaya gerek yok.</para>
///
/// <para>⚠️ Bu değerler, sırrı wrap'leyen bootstrap script'lerindeki
/// <c>--encryption-context</c> ile <b>BİREBİR</b> aynı olmalıdır; aksi halde Decrypt
/// <c>InvalidCiphertextException</c> ile düşer.
/// Bkz. <c>tools/ticket-mac-setup.ps1</c> ve <c>tools/identity-hmac-setup.ps1</c>.</para>
/// </summary>
public static class KmsPurpose
{
    /// <summary>Bilet mühürleme (HMAC) sırrı — <see cref="TicketMacService"/>.</summary>
    public const string TicketMac = "ticket-mac";

    /// <summary>Kimlik takma adı türetme (HMAC) sırrı — <see cref="IdentityHmacService"/>.</summary>
    public const string IdentityHmac = "identity-hmac";
}

public interface IKmsService
{
    /// <summary>
    /// Attestation-bound KMS Decrypt (Nitro Recipient). <paramref name="ciphertext"/> wrapping CMK ile
    /// sarılmış blob'tur; <paramref name="attestationDocument"/> enclave'in ephemeral public key'ini
    /// (public_key alanında) taşıyan TAZE attestation belgesidir. KMS, key policy'deki PCR0 koşulunu
    /// doğrular ve plaintext'i enclave'in ephemeral public key'ine RSAES_OAEP_SHA_256 ile şifreleyip
    /// CiphertextForRecipient (CMS/PKCS7) olarak döner. Dönen CMS, enclave'in ephemeral private key'iyle
    /// (<see cref="IEnclaveKeyService.DecryptCmsForRecipient"/>) açılır.
    ///
    /// <para><paramref name="purpose"/> EncryptionContext'in <c>purpose</c> alanına gider ve sırrı
    /// wrap'leyen script'teki değerle birebir eşleşmelidir (bkz. <see cref="KmsPurpose"/>).
    /// Yanlış amaç → KMS ciphertext'i açmayı REDDEDER (AAD uyuşmazlığı).</para>
    ///
    /// Yalnız KMS_MODE=aws + gerçek Nitro donanımında kullanılır.
    /// </summary>
    Task<byte[]> DecryptWithAttestationAsync(byte[] ciphertext, byte[] attestationDocument, string purpose);
}
