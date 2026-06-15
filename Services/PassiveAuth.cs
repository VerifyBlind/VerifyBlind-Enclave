using System.Collections.Concurrent;
using System.Text;

namespace VerifyBlind.Enclave.Services;

#pragma warning disable SYSLIB0057 // Suppress obsolete X509Certificate2 constructor warning

/// <summary>
/// ICAO 9303 Passive Authentication: verifies the SOD signature against the CSCA trust chain,
/// performs offline CRL revocation checks, and binds each data group's hash to its slot in the
/// SOD's LDSSecurityObject (DG1/DG2/DG15). Extracted from EnclaveService (god-class split);
/// register/login behaviour is unchanged.
/// </summary>
public static class PassiveAuth
{
    // Cache for Trusted Certificates by Country (e.g., "TUR" -> Collection)
    private static readonly ConcurrentDictionary<string, System.Security.Cryptography.X509Certificates.X509Certificate2Collection> _countryCertsCache = new();

    // Cache for CRL entries by Country (e.g., "TUR" -> list of revoked serial numbers)
    private static readonly ConcurrentDictionary<string, HashSet<string>> _countryCrlCache = new();
    /// <summary>Verifies passive auth and returns a short DG-hash summary (e.g. "DG1:LDS DG2:LDS DG15:LDS")
    /// for the relay-visible diag. Throws on any failure.</summary>
    internal static string Verify(string sodBase64, string dg1Base64, string dg2Base64, string dg15Base64)
    {
        Console.WriteLine("[Enclave] Pasif Kimlik Doğrulama başlatılıyor (CSCA Kontrolü + DG Hash Doğrulaması)...");
        
// 1. Get Country from DG1 to find correct CSCA folder
        var countryCode = MrzParser.GetIssuingCountryFromDG1(dg1Base64);
        Console.WriteLine($"[Enclave] Belge Ülkesi: {countryCode}. CSCA/{countryCode} yükleniyor...");
        
        // 2. Load/Cache certificates for this specific country
        var certs = _countryCertsCache.GetOrAdd(countryCode, (code) => LoadCscaCertificatesInternal(code));

        Console.WriteLine($"[Enclave] Ülke Güven Deposu kullanılıyor ({countryCode}): {certs.Count} sertifika mevcut.");

        if (certs.Count == 0)
            throw new Exception($"Çip doğrulama yapılamadığından bu kart desteklenmemektedir ({countryCode} için CSCA sertifikası bulunamadı).");

        // 2. Parse SOD (PKCS#7 Signed Data)
        byte[] sodBytes = Convert.FromBase64String(sodBase64);
        
        // SIMULATION BYPASS
        try {
            var sodStr = Encoding.UTF8.GetString(sodBytes);
        } catch {}
        
        Console.WriteLine("[Enclave] SOD sahte değil. GERÇEK Pasif Kimlik Doğrulama başlatılıyor...");

        // FIX: Unwrap ICAO Application Tag 0x77 if present
        try 
        {
            // Use AsnDecoder to parse the tag and find content offset
            var tag = System.Formats.Asn1.Asn1Tag.Decode(sodBytes, out int _);
            if (tag.TagClass == System.Formats.Asn1.TagClass.Application && tag.TagValue == 23)
            {
                Console.WriteLine("[Enclave] SOD'dan ICAO Etiketi 0x77 çözülüyor...");
                System.Formats.Asn1.AsnDecoder.ReadEncodedValue(
                    sodBytes, 
                    System.Formats.Asn1.AsnEncodingRules.BER, 
                    out int contentOffset, 
                    out int contentLength, 
                    out int _);
                
                // Extract inner content (SignedData)
                sodBytes = sodBytes.AsSpan(contentOffset, contentLength).ToArray();
            }
        }
        catch (Exception asnEx)
        {
            Console.WriteLine($"[Enclave] Etiket Çözme Uyarısı: {asnEx.Message}. Ham baytlarla devam ediliyor.");
        }

        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms();
try
        {
            signedCms.Decode(sodBytes);
        }
        catch (System.Security.Cryptography.CryptographicException cex)
        {
            Console.WriteLine($"[Enclave] SOD Çözme BAŞARISIZ (CryptographicException): {cex.Message}");
            Console.WriteLine($"[Enclave] SOD ham baytlar ({sodBytes.Length}): {Convert.ToHexString(sodBytes.AsSpan(0, Math.Min(64, sodBytes.Length)))}...");
            throw new Exception($"Pasif Kimlik Doğrulama Başarısız: SOD yapısı çözümlenemedi. ({cex.Message})");
        } 

        // 3. Verify Signature against Trust Store
        try 
        {
            // First, basic signature check (integrity)
try
            {
                signedCms.CheckSignature(true); 
            }
            catch (System.Security.Cryptography.CryptographicException cex)
            {
                Console.WriteLine($"[Enclave] SOD CheckSignature BAŞARISIZ: {cex.Message}");
                // Log the signer info for debugging
                if (signedCms.SignerInfos.Count > 0)
                {
                    var si = signedCms.SignerInfos[0];
                    Console.WriteLine($"[Enclave] İmzacı DigestAlgorithm: {si.DigestAlgorithm.FriendlyName} ({si.DigestAlgorithm.Value})");
                    if (si.Certificate != null)
                        Console.WriteLine($"[Enclave] İmzacı Sertifikası: {si.Certificate.Subject}");
                }
                throw new Exception($"Pasif Kimlik Doğrulama Başarısız: SOD imza doğrulaması başarısız. ({cex.Message})");
            } 
            Console.WriteLine("[Enclave] SOD İmza Bütünlüğü Geçerli.");
            
            // Now check Chain of Trust
            var signer = signedCms.SignerInfos[0];
            var dsCert = signer.Certificate;
            
            if (dsCert == null) throw new Exception("SOD içinde sertifika yok.");

            Console.WriteLine($"[Enclave] DS Konusu: {dsCert.Subject}");
            Console.WriteLine($"[Enclave] DS Yayıncısı:  {dsCert.Issuer}");

            // Extract Authority Key Identifier (AKID) - OID 2.5.29.35
            var akidExt = dsCert.Extensions["2.5.29.35"];
            if (akidExt != null)
            {
                Console.WriteLine($"[Enclave] DS Üst ID talep ediyor (AKID): {Convert.ToHexString(akidExt.RawData)}");
            }
            
            bool trusted = false;
            
            // Native .NET Chain Build (Enforces strictly authenticated paths + CRLs)
            using (var chain = new System.Security.Cryptography.X509Certificates.X509Chain())
            {
                // AWS/Docker ortamlarından cgv.nvi.gov.tr gibi devlet CRL sunucularına 
                // erişim (Geo-Block/Firewall nedeniyle) 30 saniyelik TCP Timeout yaratıyor!
                // Bu yüzden Online CRL şimdilik devre dışı bırakıldı (35 saniye gecikme çözümü).
                chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = System.Security.Cryptography.X509Certificates.X509VerificationFlags.AllowUnknownCertificateAuthority;
                
                // Use ExtraStore as fallback for the native builder
                chain.ChainPolicy.ExtraStore.AddRange(certs);

                // Build the chain
                bool buildResult = false;
                try 
                {
                    buildResult = chain.Build(dsCert);
                }
                catch (System.Security.Cryptography.CryptographicException cex)
                {
                    Console.WriteLine($"[Enclave] X509Chain.Build CryptographicException fırlattı: {cex.Message}. Manuel BouncyCastle doğrulamaya geçiliyor...");
                }

                if (buildResult)
                {
                    // Check if the root of the chain is in our Trusted List
                    var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate; 
                    var found = certs.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, root.Thumbprint, false);
                    if (found.Count > 0)
                    {
                        trusted = true;
                        Console.WriteLine($"[Enclave] Zincir Güvenilir Köke doğrulandı: {root.Subject}");
                    }
                    else 
                    {
                        Console.WriteLine($"[Enclave] Zincir Kökü: {root.Subject} Güven Deposunda bulunamadı.");
                    }
                }
                else 
                {
Console.WriteLine("[Enclave] ORS Zincir İnşası başarısız. Durumlar kontrol ediliyor...");
                     foreach(var status in chain.ChainStatus)
                     {
                         Console.WriteLine($"[Enclave] Zincir Durumu: {status.Status} - {status.StatusInformation}");
                     }
                }
            }
            
            // FALLBACK: Manual BouncyCastle Signature Verification
            // Linux/Docker ortamında OS Root Store (.NET ExtraStore bug'ı) çalışmadığında 
            // işlemi kurtarmak için hayat kurtaran saf kriptografik doğrulama.
            if (!trusted)
            {
                Console.WriteLine("[Enclave] Zincir Doğrulaması için Manuel BouncyCastle Yedeğine başvuruluyor...");
                try 
                {
                    // Convert .NET Cert to BouncyCastle Cert
                    var parser = new Org.BouncyCastle.X509.X509CertificateParser();
                    var bcDsCert = parser.ReadCertificate(dsCert.RawData);

                    foreach (var csca in certs)
                    {
                        try 
                        {
                            var bcCsca = parser.ReadCertificate(csca.RawData);
                            // Verify dsCert signature using csca's public key
                            bcDsCert.Verify(bcCsca.GetPublicKey());
                            
                            // If we reach here, it's valid!
                            trusted = true;
                            Console.WriteLine($"[Enclave] MANUEL DOĞRULAMA BAŞARILI ✓ İmzalayan: {csca.Subject}");
                            break; 
                        }
                        catch { /* Try next CSCA */ }
                    }
                }
                catch (Exception exBc)
                {
                    Console.WriteLine($"[Enclave] Manuel BC doğrulaması başarısız: {exBc.Message}");
                }
            }
            
            if (!trusted)
            {
                var sha256 = Convert.ToHexString(dsCert.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));
                Console.WriteLine($"[Enclave] Zincir Doğrulaması Başarısız ❌ Yayıncı: '{dsCert.Issuer}' SHA-256: {sha256}");
                throw new Exception($"Çip doğrulama yapılamadığından bu kart desteklenmemektedir (kart sertifikası güvenilir CSCA ile doğrulanamadı).");
            }

            // 3b. Offline CRL Check — DSC iptal edilmiş mi kontrol et
            CheckCertificateRevocation(dsCert, countryCode);
        }
        catch (Exception ex)
        {
Console.WriteLine($"[Enclave] SOD Doğrulaması Başarısız: {ex}");
            // Wrap ALL exceptions (including CryptographicException) with context
            throw new Exception($"SOD Zincir Doğrulaması Başarısız: {ex.Message}", ex); 
        }

        // 4. Verify DG Hashes against SOD Content
        Console.WriteLine("[Enclave] Veri Grubu Hash'leri doğrulanıyor...");
        var dgSummary = VerifyDGHashes(signedCms.ContentInfo.Content, dg1Base64, dg2Base64, dg15Base64);

        Console.WriteLine("[Enclave] Pasif Kimlik Doğrulama (SOD İmzası + DG Hash Doğrulaması) TAMAMLANDI ✓");
        // Returned summary is surfaced in the relay-visible diag (e.g. "DG1:LDS DG2:LDS DG15:LDS"),
        // so DG2 binding can be confirmed from normal logs without the enclave console.
        return dgSummary;
    }

    internal static string VerifyDGHashes(byte[] sodContent, string dg1Base64, string dg2Base64, string dg15Base64)
    {
        // Parse the ICAO 9303 LDSSecurityObject ONCE: it maps each data-group number to its expected
        // hash. When parsing succeeds we bind each DG to its OWN slot (DG1→[1], DG2→[2], DG15→[15]) —
        // strictly stronger than the legacy "is this hash present somewhere in the SOD" scan, which
        // ignored the DG number entirely. If parsing fails (malformed-but-validly-signed SOD) we fall
        // back to that scan so a genuine, validly-signed card is never rejected.
        var lds = TryParseLdsSecurityObject(sodContent);
        if (lds != null)
            Console.WriteLine($"[Enclave] LDSSecurityObject ayrıştırıldı: algo={lds.DigestAlgorithm}, {lds.Hashes.Count} DG hash slotu.");

        var summary = new List<string>();

        // DG1 (MRZ) — required.
        summary.Add("DG1:" + VerifyOneDgHash(sodContent, lds, dgNumber: 1, dgBase64: dg1Base64, required: true));

        // DG2 (face) — required. Without this the biometric photo is NOT cryptographically bound to
        // the document: an attacker could pair a genuine SOD/DG1 with a substituted face and still
        // pass the face match. The raw DG2 bytes (not the re-encoded DG2_Photo) must be supplied by
        // the client. (Security review Y-3.)
        summary.Add("DG2:" + VerifyOneDgHash(sodContent, lds, dgNumber: 2, dgBase64: dg2Base64, required: true));

        // DG15 (Active Authentication public key) — only present on chip-auth capable cards.
        if (!string.IsNullOrEmpty(dg15Base64))
            summary.Add("DG15:" + VerifyOneDgHash(sodContent, lds, dgNumber: 15, dgBase64: dg15Base64, required: true));

        return string.Join(" ", summary); // e.g. "DG1:LDS DG2:LDS DG15:LDS" (LDS=strict slot, scan=fallback)
    }

    /// <summary>
    /// Verifies a single data group's hash against the SOD. Strict when the LDSSecurityObject parsed
    /// (compares against that DG's exact slot); otherwise falls back to the legacy multi-algorithm scan.
    /// </summary>
    // Returns "LDS" (strict slot match), "scan" (fallback scan match) or "absent" (optional DG not sent).
    private static string VerifyOneDgHash(byte[] sodContent, LdsSecurityObject? lds, int dgNumber, string dgBase64, bool required)
    {
        if (string.IsNullOrEmpty(dgBase64))
        {
            if (required)
                throw new Exception($"DG{dgNumber} eksik — SOD bağlama doğrulaması yapılamıyor (istemci ham DG{dgNumber} baytlarını göndermeli).");
            return "absent";
        }

        byte[] dgBytes;
        try { dgBytes = Convert.FromBase64String(dgBase64); }
        catch { throw new Exception($"DG{dgNumber} Base64 çözümlenemedi."); }

        // Candidate byte representations. Some readers strip the outer TLV wrapper (DG tags 0x61/0x75/
        // 0x6F or context tag 0x5F); also try the inner content so a valid card is never rejected.
        var candidates = new List<byte[]> { dgBytes };
        if (dgBytes.Length > 2 && (dgBytes[0] == 0x61 || dgBytes[0] == 0x75 || dgBytes[0] == 0x6F || dgBytes[0] == 0x5F))
        {
            int skip = (dgBytes[1] & 0x80) == 0 ? 2 : 2 + (dgBytes[1] & 0x7F);
            if (dgBytes.Length > skip) candidates.Add(dgBytes.AsSpan(skip).ToArray());
        }

        // Strict path: LDS parsed and carries a slot for this DG → the computed hash must equal it.
        if (lds != null && lds.Hashes.TryGetValue(dgNumber, out var expected))
        {
            foreach (var cand in candidates)
            {
                var actual = HashWith(lds.DigestAlgorithm, cand);
                if (actual.Length == expected.Length &&
                    System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(actual, expected))
                {
                    Console.WriteLine($"[Enclave] DG{dgNumber} Hash DOĞRULANDI ✓ (LDS slotu, {lds.DigestAlgorithm})");
                    return "LDS";
                }
            }
            throw new Exception($"DG{dgNumber} Hash Uyuşmazlığı! Hesaplanan hash, SOD'daki DG{dgNumber} slotuyla eşleşmiyor ({lds.DigestAlgorithm}). Belge ile bu veri grubu uyuşmuyor.");
        }

        // Fallback path: LDS could not be parsed (or had no slot for this DG) → legacy multi-algorithm scan.
        Console.WriteLine($"[Enclave] DG{dgNumber}: LDS slotu yok, yedek SOD taramasına geçiliyor.");
        string[] algos = { "SHA-256", "SHA-1", "SHA-384", "SHA-512" };
        foreach (var algo in algos)
        {
            foreach (var cand in candidates)
            {
                var actual = HashWith(algo, cand);
                if (SearchHashInSOD(sodContent, dgNumber, actual))
                {
                    Console.WriteLine($"[Enclave] DG{dgNumber} Hash DOĞRULANDI ✓ (yedek tarama, {algo})");
                    return "scan";
                }
            }
        }
        throw new Exception($"DG{dgNumber} Hash Uyuşmazlığı! (SHA-1/256/384/512 ile SOD'da eşleşme bulunamadı). NFC okuma sırasında veri bozulması olabilir.");
    }

    private static byte[] HashWith(string algo, byte[] data)
    {
        using var hasher = System.Security.Cryptography.IncrementalHash.CreateHash(
            new System.Security.Cryptography.HashAlgorithmName(algo.Replace("-", "")));
        hasher.AppendData(data);
        return hasher.GetHashAndReset();
    }

    /// <summary>Parsed view of the ICAO 9303 Part 10 LDSSecurityObject.</summary>
    internal sealed class LdsSecurityObject
    {
        public string DigestAlgorithm { get; init; } = ""; // normalized, e.g. "SHA-256"
        public Dictionary<int, byte[]> Hashes { get; init; } = new(); // dataGroupNumber → expected hash
    }

    /// <summary>
    /// Parses the LDSSecurityObject carried in the SOD eContent into a (digest algorithm,
    /// {dataGroupNumber → hash}) map. Returns null on ANY parse failure so the caller can fall back
    /// to the legacy scan (we must never reject a genuine, validly-signed card on a parse quirk).
    ///   LDSSecurityObject ::= SEQUENCE { version INTEGER, hashAlgorithm AlgorithmIdentifier,
    ///                                    dataGroupHashValues SEQUENCE OF DataGroupHash, ... }
    ///   DataGroupHash     ::= SEQUENCE { dataGroupNumber INTEGER, dataGroupHashValue OCTET STRING }
    /// </summary>
    internal static LdsSecurityObject? TryParseLdsSecurityObject(byte[] sodContent)
    {
        try
        {
            var reader = new System.Formats.Asn1.AsnReader(sodContent, System.Formats.Asn1.AsnEncodingRules.BER);
            var lds = reader.ReadSequence();
            lds.ReadInteger(); // version
            var algId = lds.ReadSequence();
            var algo = MapDigestOid(algId.ReadObjectIdentifier());
            if (algo == null) return null; // unknown digest OID → cannot hash, use fallback

            var dgValues = lds.ReadSequence();
            var hashes = new Dictionary<int, byte[]>();
            while (dgValues.HasData)
            {
                var dgHash = dgValues.ReadSequence();
                int dgNum = (int)dgHash.ReadInteger();
                hashes[dgNum] = dgHash.ReadOctetString();
            }
            return hashes.Count > 0 ? new LdsSecurityObject { DigestAlgorithm = algo, Hashes = hashes } : null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] LDSSecurityObject ASN.1 ayrıştırılamadı (yedek taramaya geçilecek): {ex.Message}");
            return null;
        }
    }

    // Maps an ICAO digest-algorithm OID to a .NET HashAlgorithmName string. Returns null for
    // algorithms we cannot compute (e.g. SHA-224 is unsupported by IncrementalHash) → triggers fallback.
    private static string? MapDigestOid(string oid) => oid switch
    {
        "1.3.14.3.2.26"          => "SHA-1",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => null
    };

    internal static bool SearchHashInSOD(byte[] sodContent, int dgNumber, byte[] expectedHash)
    {
        // Simple search: look for the hash bytes in SOD content
        // In production, properly parse the ASN.1 structure
        
        // Convert to hex for logging
        var expectedHex = Convert.ToHexString(expectedHash);
        
        // Brute force search for the hash in SOD content
        for (int i = 0; i <= sodContent.Length - expectedHash.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < expectedHash.Length; j++)
            {
                if (sodContent[i + j] != expectedHash[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                Console.WriteLine($"[Enclave] DG{dgNumber} hash SOD'da {i} ofsetinde bulundu");
                return true;
            }
        }
        
        Console.WriteLine($"[Enclave] UYARI: DG{dgNumber} hash SOD içeriğinde bulunamadı (Beklenen: {expectedHex[..Math.Min(16, expectedHex.Length)]}...)");
        return false;
    }

private static void CheckCertificateRevocation(System.Security.Cryptography.X509Certificates.X509Certificate2 dsCert, string countryCode)
    {
        var revokedSerials = _countryCrlCache.GetOrAdd(countryCode, LoadCrlEntriesInternal);

        if (revokedSerials.Count == 0)
        {
            Console.WriteLine($"[Enclave] CRL/{countryCode}: CRL dosyasi yok veya bos, CRL kontrolu atlanıyor.");
            return;
        }

        // .NET SerialNumber bastaki sifirlarla pad edebilir, normalize et
        var dsSerial = dsCert.SerialNumber.TrimStart('0').ToUpperInvariant();
        Console.WriteLine($"[Enclave] CRL kontrolu: DS seri no={dsSerial}, CRL'de {revokedSerials.Count} iptal kaydi.");

        if (revokedSerials.Contains(dsSerial))
        {
            throw new Exception($"Sertifika İptal Edilmiş! ❌ DS sertifikası (Seri: {dsSerial}) CRL'de iptal edilmiş olarak işaretli. Bu belgenin imzası artık güvenilir değil.");
        }

        Console.WriteLine("[Enclave] CRL kontrolu GECTI ✓ DS sertifikasi iptal listesinde degil.");
    }

    private static HashSet<string> LoadCrlEntriesInternal(string countryCode)
    {
        var revoked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string crlPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Certificates", "CRL", countryCode);
        if (!Directory.Exists(crlPath))
        {
            crlPath = Path.Combine(Directory.GetCurrentDirectory(), "Certificates", "CRL", countryCode);
        }
        if (!Directory.Exists(crlPath))
        {
            return revoked;
        }

        var files = Directory.GetFiles(crlPath, "*.crl");
        Console.WriteLine($"[Enclave] CRL/{countryCode}: {files.Length} CRL dosyasi bulundu.");

        var parser = new Org.BouncyCastle.X509.X509CrlParser();

        foreach (var file in files)
        {
            try
            {
                var bytes = File.ReadAllBytes(file);
                var crl = parser.ReadCrl(bytes);

                var revokedCerts = crl.GetRevokedCertificates();
                if (revokedCerts == null) continue;

                foreach (Org.BouncyCastle.X509.X509CrlEntry entry in revokedCerts)
                {
                    // BouncyCastle BigInteger.ToString(16) bastaki sifirlari keser
                    // .NET SerialNumber pad edebilir, her ikisini de TrimStart('0') ile normalize ediyoruz
                    var hex = entry.SerialNumber.ToString(16).TrimStart('0').ToUpperInvariant();
                    if (hex.Length > 0) revoked.Add(hex);
                }

                Console.WriteLine($"[Enclave] CRL/{countryCode}/{Path.GetFileName(file)}: {revokedCerts.Count} iptal kaydi yuklendi.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Enclave] CRL/{countryCode}/{Path.GetFileName(file)} yuklenemedi: {ex.Message}");
            }
        }

        return revoked;
    }

    private static System.Security.Cryptography.X509Certificates.X509Certificate2Collection LoadCscaCertificatesInternal(string countryCode)
    {
        Console.WriteLine($"[Enclave] {countryCode} için Güvenilir Kök Deposu diskten başlatılıyor...");
        var collection = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
        
        // Path: Certificates/CSCA/{CountryCode}
        string certPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Certificates", "CSCA", countryCode);
        
        if (!Directory.Exists(certPath))
        {
             certPath = Path.Combine(Directory.GetCurrentDirectory(), "Certificates", "CSCA", countryCode); 
        }

        if (Directory.Exists(certPath))
        {
            var files = Directory.GetFiles(certPath, "*.*"); 
Console.WriteLine($"[Enclave] CSCA/{countryCode} klasöründe {files.Length} dosya bulundu.");
            foreach (var file in files)
            {
                try 
                {
                    // Check for Master List (PKCS#7)
                    if (file.EndsWith(".ml", StringComparison.OrdinalIgnoreCase) || 
                        file.EndsWith(".masterlist", StringComparison.OrdinalIgnoreCase) ||
                        file.EndsWith(".p7b", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"[Enclave] Master List okunuyor: {Path.GetFileName(file)}");
                        byte[] bytes = File.ReadAllBytes(file);
                        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms();
                        signedCms.Decode(bytes);
                        
                        if (signedCms.Certificates.Count > 0)
                        {
                            collection.AddRange(signedCms.Certificates);
                        }
                        
                        // Extract Inner Content for pure certs in ML
                        try 
                        {
                            var contentBytes = signedCms.ContentInfo.Content;
                            if (contentBytes != null && contentBytes.Length > 0)
                            {
                                 var reader = new System.Formats.Asn1.AsnReader(contentBytes, System.Formats.Asn1.AsnEncodingRules.BER);
                                 var sequence = reader.ReadSequence();
                                 
                                 // Skip Version
                                 if (sequence.PeekTag().HasSameClassAndValue(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.UniversalTagNumber.Integer)))
                                 {
                                     sequence.ReadInteger();
                                 }
                                 
                                 var nextTag = sequence.PeekTag();
                                 System.Formats.Asn1.AsnReader certSetReader;
                                 if (nextTag.TagValue == (int)System.Formats.Asn1.UniversalTagNumber.SetOf)
                                 {
                                     certSetReader = sequence.ReadSetOf();
                                 }
                                 else 
                                 {
                                     certSetReader = sequence.ReadSetOf();
                                 }

                                 int count = 0;
                                 while (certSetReader.HasData)
                                 {
                                     var certBytes = certSetReader.ReadEncodedValue().ToArray();
                                     try 
                                     {
                                        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certBytes);
                                        collection.Add(cert);
                                        count++;
                                     } 
                                     catch { }
                                 }
                                 Console.WriteLine($"[Enclave] Master List yükünden {count} sertifika içe aktarıldı.");
                            }
                        }
                        catch { /* Ignore ML parse errors for now */ }
                    }
                    else if (file.EndsWith(".pem", StringComparison.OrdinalIgnoreCase) ||
                             file.EndsWith(".crt", StringComparison.OrdinalIgnoreCase))
                    {
                        // Text-based PEM or DER
                        try 
                        {
                            var text = File.ReadAllText(file);
                            if (text.Contains("-----BEGIN CERTIFICATE-----"))
                            {
                                var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(text);
                                collection.Add(cert);
                            }
                            else
                            {
                                // Likely binary DER with .crt extension
                                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(file);
                                collection.Add(cert);
                            }
                        }
                        catch (Exception exPem)
                        {
                            Console.WriteLine($"[Enclave] {Path.GetFileName(file)} için PEM yüklemesi başarısız, binary yedek deneniyor... Hata: {exPem.Message}");
                             // Fallback to binary load
                            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(file);
                            collection.Add(cert);
                        }
                    }
                    else
                    {
                        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(file);
                        collection.Add(cert);
                    }
                }
                catch (Exception ex)
                { 
                    Console.WriteLine($"[Enclave] {Path.GetFileName(file)} yüklenemedi: {ex.Message}");
                }
            }
        }
        Console.WriteLine($"[Enclave] Güven Deposu başlatıldı. Toplam Sertifika: {collection.Count}");
        return collection;
    }
}
