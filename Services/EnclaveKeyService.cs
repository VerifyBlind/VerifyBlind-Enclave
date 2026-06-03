using VerifyBlind.Core.Crypto;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// IEnclaveKeyService implementation. Enclave RSA key pair is generated per-instance
/// at startup. Attestation document binds the public key to NSM hardware.
/// </summary>
public class EnclaveKeyService : IEnclaveKeyService
{
    private readonly string _enclavePrivKey;
    private readonly string _enclavePubKey;
    private readonly INsmProvider _nsm;
    private string? _cachedAttestationDoc;
    private DateTime _attestationCachedAt = DateTime.MinValue;
    private static readonly TimeSpan AttestationCacheTtl = TimeSpan.FromMinutes(150); // 2.5 saat — sertifika ~3 saat geçerli

    public EnclaveKeyService(INsmProvider nsm)
    {
        _nsm = nsm;
        using var rsa = RSA.Create(2048);
        _enclavePrivKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
        _enclavePubKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
        Console.WriteLine("[EnclaveKeyService] Per-instance RSA-2048 key oluşturuldu.");
    }

    public string GetEnclavePublicKey() => _enclavePubKey;
    public string SignDataWithEnclaveKey(string data) => CryptoUtils.SignData(data, _enclavePrivKey);
    public bool VerifyEnclaveSignature(string data, string signature) =>
        CryptoUtils.VerifySignature(data, signature, _enclavePubKey);
    public string DecryptWithEnclaveKey(string cipherText) =>
        CryptoUtils.RsaDecrypt(cipherText, _enclavePrivKey);

    public string GetAttestationDocument()
    {
        if (_cachedAttestationDoc != null && DateTime.UtcNow - _attestationCachedAt < AttestationCacheTtl)
            return _cachedAttestationDoc;

        bool isRefresh = _cachedAttestationDoc != null;
        var pubKeyBytes = Encoding.UTF8.GetBytes(_enclavePubKey);
        var docBytes = _nsm.GetAttestationDocument(userData: pubKeyBytes);
        _cachedAttestationDoc = Convert.ToBase64String(docBytes);
        _attestationCachedAt = DateTime.UtcNow;
        Console.WriteLine($"[EnclaveKeyService] Attestation belgesi {(isRefresh ? "yenilendi" : "oluşturuldu")} ve önbelleğe alındı.");
        return _cachedAttestationDoc;
    }

    public byte[] GetAttestationDocumentForRecipient()
    {
        // public_key = ephemeral RSA pubkey'in DER SubjectPublicKeyInfo'su → KMS bu alana şifreler.
        // userData = aynı pubkey (handshake davranışıyla tutarlı, PCR0 yine belgede).
        var pubKeyDer = Convert.FromBase64String(_enclavePubKey);
        var userData = Encoding.UTF8.GetBytes(_enclavePubKey);
        return _nsm.GetAttestationDocument(userData: userData, nonce: null, publicKey: pubKeyDer);
    }

    public byte[] DecryptCmsForRecipient(byte[] cmsForRecipient)
    {
        // CiphertextForRecipient = CMS/PKCS7 EnvelopedData (KEK: RSAES_OAEP_SHA_256).
        // BouncyCastle ile ephemeral RSA private key kullanarak aç.
        var privKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(_enclavePrivKey));
        var enveloped = new CmsEnvelopedData(cmsForRecipient);
        foreach (RecipientInformation recipient in enveloped.GetRecipientInfos().GetRecipients())
        {
            return recipient.GetContent(privKey);
        }
        throw new InvalidOperationException("CiphertextForRecipient (CMS) içinde recipient bulunamadı.");
    }
}
