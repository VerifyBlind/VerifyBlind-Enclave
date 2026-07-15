using VerifyBlind.Core.Crypto;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    // Belgeyi bu UTC ana kadar cache'le; ulaşınca NSM'den yeniden mint et.
    private DateTime _attestationRefreshAt = DateTime.MinValue;
    // Leaf sertifika parse edilemezse (mock/dev belge) kullanılan yedek sabit TTL.
    private static readonly TimeSpan AttestationFallbackTtl = TimeSpan.FromMinutes(150);
    // Leaf sertifikanın gerçek son-geçerliliğinden ne kadar ÖNCE yenilensin (emniyet payı).
    private static readonly TimeSpan AttestationRefreshMargin = TimeSpan.FromMinutes(30);

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
        if (_cachedAttestationDoc != null && DateTime.UtcNow < _attestationRefreshAt)
            return _cachedAttestationDoc;

        bool isRefresh = _cachedAttestationDoc != null;
        var pubKeyBytes = Encoding.UTF8.GetBytes(_enclavePubKey);
        var docBytes = _nsm.GetAttestationDocument(userData: pubKeyBytes);
        _cachedAttestationDoc = Convert.ToBase64String(docBytes);

        // Tazeleme penceresini leaf sertifikanın GERÇEK son-geçerliliğine bağla (notAfter - margin).
        // AWS, sertifikayı kendi (doğru) saatiyle damgalar; bu yüzden saat senkronlu enclave'de bu
        // yaklaşım sabit "~3 saat" varsayımından daha sağlam — sertifikanın gerçek ömrüne uyar ve
        // sınıra hiç yaklaşmaz. Parse edilemezse (mock/dev belge, COSE değil) eski sabit TTL'ye düş.
        // NOT: Saat kaymasına karşı tek başına yeterli DEĞİL (kıyas hâlâ enclave saatiyle); asıl
        // koruma chrony saat senkronu + relay-tarafı tazelik kontrolü.
        var notAfter = TryGetLeafCertNotAfter(docBytes);
        _attestationRefreshAt = notAfter.HasValue
            ? notAfter.Value.UtcDateTime - AttestationRefreshMargin
            : DateTime.UtcNow + AttestationFallbackTtl;

        Console.WriteLine(
            $"[EnclaveKeyService] Attestation belgesi {(isRefresh ? "yenilendi" : "oluşturuldu")}; " +
            $"sonraki tazeleme ~{_attestationRefreshAt:o} (leaf notAfter: {(notAfter?.UtcDateTime.ToString("o") ?? "bilinmiyor/mock")}).");
        return _cachedAttestationDoc;
    }

    /// <summary>
    /// COSE_Sign1 attestation belgesinin payload'undaki leaf sertifikanın (AWS damgalı, "certificate"
    /// alanı) son geçerlilik tarihini döndürür. Mock/dev belge (CBOR map, COSE array değil) veya parse
    /// hatasında <c>null</c>. Relay <c>PcrSignatureResolver.GetLeafCertNotAfter</c> ile aynı mantık
    /// (ayrı güven alanları olduğu için kasıtlı iki kopya).
    /// </summary>
    private static DateTimeOffset? TryGetLeafCertNotAfter(byte[] coseDocBytes)
    {
        try
        {
            var reader = new CborReader(coseDocBytes);
            if (reader.PeekState() != CborReaderState.StartArray) return null; // mock map → gerçek sertifika yok

            int? arrayLen = reader.ReadStartArray();   // COSE_Sign1: [protected, unprotected, payload, sig]
            reader.ReadByteString();                    // 0: Protected Header
            reader.SkipValue();                         // 1: Unprotected Header
            byte[] payloadBytes = reader.ReadByteString(); // 2: Payload
            reader.SkipValue();                         // 3: Signature
            if (arrayLen == null) reader.ReadEndArray();

            var p = new CborReader(payloadBytes);
            int? mapSize = p.ReadStartMap();
            int items = 0;
            byte[]? leafDer = null;
            while (mapSize == null || items < mapSize.Value)
            {
                if (p.PeekState() == CborReaderState.EndMap) break;
                if (p.PeekState() == CborReaderState.TextString)
                {
                    string key = p.ReadTextString();
                    if (key == "certificate") leafDer = p.ReadByteString();
                    else p.SkipValue();
                }
                else
                {
                    p.SkipValue(); // key
                    p.SkipValue(); // value
                }
                items++;
            }
            if (mapSize == null) p.ReadEndMap();

            if (leafDer == null) return null;
            using var cert = X509CertificateLoader.LoadCertificate(leafDer);
            return new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        }
        catch
        {
            return null;
        }
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
