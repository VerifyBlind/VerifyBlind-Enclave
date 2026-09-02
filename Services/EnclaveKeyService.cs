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
    private readonly RelayClock _relayClock;
    private string? _cachedAttestationDoc;
    // Belgeyi bu UTC ana kadar cache'le; ulaşınca NSM'den yeniden mint et.
    private DateTime _attestationRefreshAt = DateTime.MinValue;
    // Son mint edilen belgenin ZİNCİRDEKİ en erken sertifika bitişi (teşhis + /health/attestation).
    private DateTimeOffset? _attestationNotAfter;
    // Relay saatinin TETİKLEDİĞİ son yenileme — bkz. MinRelayDrivenRefreshInterval.
    private DateTime _lastRelayDrivenRefreshAt = DateTime.MinValue;
    // Relay saatiyle tetiklenen yenilemeler için alt sınır: bozuk/yalan bir saat yenileme
    // fırtınası yaratmasın. Enclave'in KENDİ saati vadeyi gösteriyorsa bu sınır uygulanmaz —
    // gerçekten bayat bir belgeyi servis etmek, fazladan NSM çağrısından çok daha kötü.
    private static readonly TimeSpan MinRelayDrivenRefreshInterval = TimeSpan.FromSeconds(60);
    // Leaf sertifika parse edilemezse (mock/dev belge) kullanılan yedek sabit TTL.
    private static readonly TimeSpan AttestationFallbackTtl = TimeSpan.FromMinutes(150);
    // Leaf sertifikanın gerçek son-geçerliliğinden ne kadar ÖNCE yenilensin (emniyet payı).
    //
    // 60 dakika: arka plan tazeleyicisi 15 dakikada bir yokluyor, yani bu pencereye en az dört tik
    // düşer. 30 dakikayken en kötü durumda tek bir kaçırılan tik payı 15 dakikaya indiriyordu —
    // sertifika 3 saatlik olduğu için bir saatlik marjın maliyeti yok, güvenliği ise belirgin.
    private static readonly TimeSpan AttestationRefreshMargin = TimeSpan.FromMinutes(60);

    public EnclaveKeyService(INsmProvider nsm, RelayClock relayClock)
    {
        _nsm = nsm;
        _relayClock = relayClock;
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

    public DateTimeOffset? AttestationNotAfter => _attestationNotAfter;
    public DateTime AttestationRefreshAt => _attestationRefreshAt;

    /// Son yenileme kararının gerekçesi — handshake yanıtına `DiagLog` ile iliştirilir ve
    /// relay loglarında görünür. Yenilemenin neden tetiklenmediğini okumanın tek yolu bu.
    public string LastRenewalDecision { get; private set; } = "(henüz karar yok)";

    public string GetAttestationDocument()
    {
        var ownNow = DateTime.UtcNow;
        var effectiveNow = _relayClock.EffectiveUtcNow;   // max(kendi saat, relay saati)

        bool haveDoc = _cachedAttestationDoc != null;
        bool dueByOwnClock  = !haveDoc || ownNow >= _attestationRefreshAt;
        bool dueByRelayOnly = haveDoc && !dueByOwnClock && effectiveNow >= _attestationRefreshAt;

        // Kararı HER ÇAĞRIDA yaz. Üretimde yenileme tetiklenmiyor ve sebebini kaynak koda bakarak
        // bulamadım: enclave saati doğru (19:32), vade geçmiş (18:56), koşul sağlanıyor GÖRÜNÜYOR
        // ama belge tazelenmiyordu. Kodun ne yaptığını okumak yerine ne yaptığını SÖYLETMEK,
        // bugün diğer tüm arızaları çözen yöntemdi.
        // ⚠️ `Console.WriteLine` ile YAZMA. Enclave'in konsolu hiçbir yere düşmüyor (systemd
        // günlüğü boş, canlı konsol sessiz) — enclave'in içini görmenin tek yolu relay'e taşınan
        // `DiagLog`. İlk denemede kararı konsola yazdım ve okunamadı.
        LastRenewalDecision =
            $"ownNow={ownNow:HH:mm:ss} effectiveNow={effectiveNow:HH:mm:ss} " +
            $"refreshAt={_attestationRefreshAt:HH:mm:ss} haveDoc={haveDoc} " +
            $"dueOwn={dueByOwnClock} dueRelay={dueByRelayOnly}";

        if (!dueByOwnClock && !dueByRelayOnly)
            return _cachedAttestationDoc!;

        // Vade YALNIZCA relay saatine göre dolmuşsa: enclave'in saati geri kalmış demektir.
        // Yenile — ama hız sınırıyla, ki yalan bir saat her isteği NSM çağrısına çevirmesin.
        if (dueByRelayOnly)
        {
            if (effectiveNow - _lastRelayDrivenRefreshAt < MinRelayDrivenRefreshInterval)
                return _cachedAttestationDoc!;
            _lastRelayDrivenRefreshAt = effectiveNow;
            var drift = _relayClock.DriftBehindRelay;
            Console.WriteLine(
                $"[EnclaveKeyService] Yenileme RELAY SAATİYLE tetiklendi — enclave saati geri kalıyor " +
                $"(fark ~{drift?.TotalMinutes:F1} dk). Kendi saatiyle vade dolmuş görünmüyordu.");
        }

        bool isRefresh = _cachedAttestationDoc != null;
        var pubKeyBytes = Encoding.UTF8.GetBytes(_enclavePubKey);
        var docBytes = _nsm.GetAttestationDocument(userData: pubKeyBytes);
        _cachedAttestationDoc = Convert.ToBase64String(docBytes);

        // Tazeleme penceresini ZİNCİRİN gerçek son-geçerliliğine bağla (en erken notAfter - margin).
        // AWS, sertifikaları kendi (doğru) saatiyle damgalar; bu yüzden saat senkronlu enclave'de bu
        // yaklaşım sabit "~3 saat" varsayımından daha sağlam — sertifikanın gerçek ömrüne uyar ve
        // sınıra hiç yaklaşmaz. Parse edilemezse (mock/dev belge, COSE değil) eski sabit TTL'ye düş.
        //
        // ⚠️ MİNİMUM leaf'inki OLMAYABİLİR: instance CA 24 saatlik ve leaf hâlâ tazeyken ölebiliyor
        // (2026-08-31 olayı). Pratikte leaf 3 saatle neredeyse her zaman minimumdur, yani bu değişim
        // yenilemeyi yalnızca ara sertifikanın son 60 dakikasında öne çeker — günde bir kez, en
        // fazla bir saatlik ek NSM trafiği. Bedeli, zincirin ölü servis edilmesinin yanında hiç.
        // NOT: Saat kaymasına karşı tek başına yeterli DEĞİL (kıyas hâlâ enclave saatiyle); asıl
        // koruma chrony saat senkronu + relay-tarafı tazelik kontrolü.
        var notAfter = TryGetChainNotAfter(docBytes);
        _attestationNotAfter = notAfter;
        // Yedek TTL de artık effectiveNow'dan sayılır: enclave saati geri kalıyorsa sabit TTL de
        // aynı oranda uzardı ve tam kaçındığımız duruma geri düşerdik.
        _attestationRefreshAt = notAfter.HasValue
            ? notAfter.Value.UtcDateTime - AttestationRefreshMargin
            : effectiveNow + AttestationFallbackTtl;

        Console.WriteLine(
            $"[EnclaveKeyService] Attestation belgesi {(isRefresh ? "yenilendi" : "oluşturuldu")}; " +
            $"sonraki tazeleme ~{_attestationRefreshAt:o} (zincirin en erken notAfter'ı: {(notAfter?.UtcDateTime.ToString("o") ?? "bilinmiyor/mock")}).");
        return _cachedAttestationDoc;
    }

    /// <summary>
    /// COSE_Sign1 attestation belgesinin payload'undaki sertifika ZİNCİRİNİN ("certificate" = leaf,
    /// "cabundle" = AWS ara sertifikaları + root) EN ERKEN biten halkasının son geçerlilik tarihini
    /// döndürür. Mock/dev belge (CBOR map, COSE array değil) veya parse hatasında <c>null</c>.
    /// Relay <c>PcrSignatureResolver.ReadChainExpiry</c> ile aynı mantık (ayrı güven alanları
    /// olduğu için kasıtlı iki kopya).
    ///
    /// ⚠️ NEDEN ZİNCİRİN TAMAMI: burası eskiden yalnız leaf'e bakıyordu ve tazeleme anı da ona
    /// bağlanıyordu. Nitro zincirinde ömürler eşit değil — leaf 3 saat, instance CA 24 saat, zonal
    /// ~6 gün — yani bir ara sertifika, leaf hâlâ tazeyken ölebiliyor ve belge o hâliyle saatlerce
    /// cache'te kalıyordu. İstemciler (iOS SecTrust, Android PKIX) zincirin tamamını denetlediği
    /// için uygulama açılmıyordu; 2026-08-31'de tam olarak bu oldu. Minimumu almak tazelemeyi
    /// yalnızca ERKENE alabilir (leaf 3 saatle neredeyse her zaman minimumdur), asla geciktirmez.
    /// </summary>
    private static DateTimeOffset? TryGetChainNotAfter(byte[] coseDocBytes)
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
            var caDers = new List<byte[]>();
            while (mapSize == null || items < mapSize.Value)
            {
                if (p.PeekState() == CborReaderState.EndMap) break;
                if (p.PeekState() == CborReaderState.TextString)
                {
                    string key = p.ReadTextString();
                    if (key == "certificate")
                    {
                        leafDer = p.ReadByteString();
                    }
                    else if (key == "cabundle")
                    {
                        // Tanımlı ya da tanımsız uzunluk: ikisinde de öğeler bitince EndArray gelir.
                        p.ReadStartArray();
                        while (p.PeekState() != CborReaderState.EndArray)
                            caDers.Add(p.ReadByteString());
                        p.ReadEndArray();
                    }
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

            DateTimeOffset? earliest = null;
            foreach (var der in caDers.Prepend(leafDer))
            {
                // Çözülemeyen bir halka = zinciri denetleyemedik. Buradaki exception aşağıdaki
                // catch'e düşer ve null döner (yedek sabit TTL) — leaf'in tarihine körü körüne
                // güvenmeye DÖNMEZ.
                using var cert = X509CertificateLoader.LoadCertificate(der);
                var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero);
                if (!earliest.HasValue || notAfter < earliest.Value) earliest = notAfter;
            }
            return earliest;
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
