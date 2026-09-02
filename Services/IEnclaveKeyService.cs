namespace VerifyBlind.Enclave.Services;

public interface IEnclaveKeyService
{
    string GetEnclavePublicKey();
    string SignDataWithEnclaveKey(string data);
    bool VerifyEnclaveSignature(string data, string signature);
    string DecryptWithEnclaveKey(string cipherText);
    string GetAttestationDocument();

    /// <summary>Son mint edilen belgenin ZİNCİRDEKİ en erken sertifika bitişi — leaf'inki
    /// olmayabilir, instance CA daha erken ölebilir (mock/çözülemeyen belgede <c>null</c>).</summary>
    DateTimeOffset? AttestationNotAfter { get; }

    /// <summary>Belgenin yenileneceği an. Saat kaymasını teşhis etmek için dışarı verilir.</summary>
    DateTime AttestationRefreshAt { get; }

    /// <summary>Son yenileme kararının gerekçesi (relay loglarına taşınır).</summary>
    string LastRenewalDecision { get; }

    /// <summary>
    /// Ephemeral RSA public key'i (DER SubjectPublicKeyInfo) attestation belgesinin public_key alanına
    /// koyan TAZE bir belge üretir (cachelenmez). KMS CiphertextForRecipient akışı bu alanı kullanır
    /// (handshake'teki <see cref="GetAttestationDocument"/> userData kullanır, public_key DEĞİL).
    /// </summary>
    byte[] GetAttestationDocumentForRecipient();

    /// <summary>
    /// KMS'in döndürdüğü CiphertextForRecipient'i (CMS/PKCS7 EnvelopedData, RSAES_OAEP_SHA_256) bu
    /// enclave'in ephemeral RSA private key'iyle açıp düz metni (ör. ticket-MAC secret) döner.
    /// Private key servis içinde kalır, dışarı çıkmaz.
    /// </summary>
    byte[] DecryptCmsForRecipient(byte[] cmsForRecipient);
}
