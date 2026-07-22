using System.Text;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// ICAO 9303 MRZ / DG1 parsing: extracts the identity fields (and TCKN / national id) from DG1 into
/// a TicketPayload, plus MRZ date and issuing-country helpers. Extracted from EnclaveService
/// (god-class split); behaviour is unchanged.
/// </summary>
public static class MrzParser
{
    /// <summary>
    /// Parses DG1 (ICAO 9303 TD1 MRZ) from Base64 to extract identity data.
    /// TD1 format: 3 lines × 30 characters
    /// Line 1: [DocType2][Country3][DocNo9][Check1][OptData15]
    /// Line 2: [DOB6][Check1][Sex1][Expiry6][Check1][Nationality3][OptData11]
    /// Line 3: [Name30] (SURNAME<<GIVENNAMES)
    /// </summary>
    internal static TicketPayload ParseDG1ToTicket(string dg1Base64, string userPubKey, string countryIsoCode)
    {
        // DG1 is TLV encoded: Tag 61 -> Tag 5F1F (MRZ data)
        var dg1Bytes = Convert.FromBase64String(dg1Base64);
        var mrzString = ExtractMrzFromDG1(dg1Bytes);

        Console.WriteLine($"[Enclave] MRZ ayrıştırıldı ({mrzString.Length} karakter): {EnclaveService.Mask(mrzString)}");

        // Yalnızca TD1 (kimlik kartı, 3×30 = 90 karakter) desteklenir. TD3 (pasaport, 2×44 = 88)
        // DocumentPolicy tarafından zaten Step 5.5'te reddedilmiştir; buraya ulaşmaz.
        if (mrzString.Length < 90)
            throw new Exception($"Invalid MRZ length: {mrzString.Length}. Expected 90 (TD1).");

        // TD1 format (ID Card): 3 lines × 30 chars
        var line1 = mrzString.Substring(0, 30);
        var line2 = mrzString.Substring(30, 30);
        var line3 = mrzString.Substring(60, 30);

        // ICAO belge kodu = line1'in ilk 2 karakteri (poz 1-2); filler '<' temizlenir.
        // "I<"→"I", "ID"→"ID". Tek karakter (line1[0]) almak 2 harfli kodun 2. harfini düşürürdü.
        var docType = line1.Substring(0, 2).Replace("<", "").Trim();

        var issuingCountry = line1.Substring(2, 3).Replace("<", "").Trim();
        var docNo = line1.Substring(5, 9).Replace("<", "").Trim();
        var dob = line2.Substring(0, 6);
        var gender = line2.Substring(7, 1);
        var expiry = line2.Substring(8, 6);
        var nationality = line2.Substring(15, 3).Replace("<", "").Trim();

        // Line 3: SURNAME<<GIVENNAMES<<<...
        var nameParts = line3.Replace("<", " ").Trim().Split(new[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
        var surname = nameParts.Length > 0 ? nameParts[0].Trim() : "";
        var givenName = nameParts.Length > 1 ? nameParts[1].Trim() : "";

        // Savunmacı: DocumentPolicy kapısı Step 5.5'te uygulanır, ama bu metot doğrudan
        // çağrılırsa (test / gelecekteki bir akış) politika sessizce atlanmasın.
        var policyVerdict = DocumentPolicy.Evaluate(issuingCountry, docType);
        if (policyVerdict != DocumentPolicy.Verdict.Accepted)
            throw new Exception($"Bu belge desteklenmemektedir (politika: {policyVerdict}).");

        Console.WriteLine($"[Enclave] DG1 Ayrıştırıldı: Ülke={issuingCountry}, Uyruk={nationality}, BelgeNo={EnclaveService.Mask(docNo)}, Cinsiyet={gender}");

        // Parse DOB (YYMMDD -> DateTime)
        var dobDate = ParseMrzDate(dob);
        var expiryDate = ParseMrzDate(expiry, isExpiry: true);

        // TCKN — TD1 İsteğe Bağlı Veri alanından (Line 1, index 15-29).
        // Boş kalabilir: aşağı akışta user_id/person_id üretilmez ve user_id partner cevabından
        // DÜŞER (bkz. IdentityCodes.IsValidTckn + EnclaveService login). Sessizce boş string
        // döndürülmesi eskiden TCKN'siz tüm kullanıcılara aynı user_id'yi verirdi.
        string primaryId = "";
        var optionalData = line1.Substring(15, 15).Replace("<", "").Trim();
        // TCKN alanın ilk 11 karakteridir; kart bu alana ek veri koyarsa kuyruğu yok sayılır
        // (eski davranış korunur), ama artık format doğrulanmadan kabul edilmez.
        var tcknCandidate = optionalData.Length >= 11 ? optionalData.Substring(0, 11) : optionalData;
        if (IdentityCodes.IsValidTckn(tcknCandidate))
        {
            primaryId = tcknCandidate;
            Console.WriteLine($"[Enclave] TD1 İsteğe Bağlı Veriden TCKN çıkarıldı: {EnclaveService.Mask(primaryId)}");
        }
        else
        {
            Console.WriteLine($"[Enclave] UYARI: TC kimlik kartında İsteğe Bağlı Veri alanı geçerli bir TCKN içermiyor: '{EnclaveService.Mask(optionalData)}'");
        }

        return new TicketPayload
        {
            TCKN = primaryId, // TCKN alınamadıysa boş — kimlik kodları buna göre düşer
            Ad = givenName,
            Soyad = surname,
            DogumTarihi = dobDate,
            SeriNo = docNo,
            GecerlilikTarihi = expiryDate,
            Cinsiyet = gender == "M" ? "M" : gender == "F" ? "F" : "<",
            Uyruk = nationality,
            UserPubKey = userPubKey,
            CountryIsoCode = countryIsoCode,
            DocumentType = docType
        };
    }

    internal static string GetIssuingCountryFromDG1(string dg1Base64)
    {
        try 
        {
            var dg1Bytes = Convert.FromBase64String(dg1Base64);
            var mrz = ExtractMrzFromDG1(dg1Bytes);
            if (!string.IsNullOrEmpty(mrz) && mrz.Length >= 5)
            {
                var country = mrz.Substring(2, 3).Replace("<", "").Trim().ToUpper();
                // Basic sanitization to prevent path traversal
                if (country.All(char.IsLetterOrDigit)) return country;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] CSCA klasörü için ülke çıkarılamadı: {ex.Message}");
        }
        return "UNKNOWN";
    }

    /// <summary>
    /// Belge politikası kapısı için gereken İKİ alanı DG1'den çıkarır: ihraç eden ülke ve ICAO
    /// belge kodu. Tam ayrıştırmadan (ParseDG1ToTicket) ayrı tutulur çünkü politika kontrolü
    /// biyometrikten ÖNCE, ucuz biçimde yapılmalıdır.
    ///
    /// <para>MRZ'nin ilk 5 karakteri her iki formatta da aynı yerleşimdedir:
    /// [BelgeKodu2][Ülke3] — TD1 "I&lt;TUR..", TD3 "P&lt;TUR..". Bu yüzden format ayrımı
    /// yapmadan okunabilir; TD3 zaten politikada reddedilecektir.</para>
    ///
    /// <returns>
    /// DG1 okunabildiyse <c>(ülke, belgeKodu)</c>. DG1 hiç çözülemediyse <c>null</c>.
    /// </returns>
    ///
    /// <para><b>null neden ayrı bir sonuç:</b> önceden burada ("", "") dönülüyordu ve politika
    /// bunu <c>UnsupportedCountry</c> olarak reddediyordu. Karar (fail-closed red) doğruydu ama
    /// TEŞHİS yanlıştı: okunamayan DG1, "belge Türkiye tarafından verilmemiş" demek DEĞİLDİR —
    /// geçerli bir TC kimliğinde de NFC/aktarım arızasıyla oluşabilir. Çağıran iki durumu farklı
    /// hata kodlarına ayırmalı ki kullanıcıya "kartınız okunamadı, tekrar deneyin" densin,
    /// "belgeniz TC değil" gibi çıkmaz bir mesaj değil.</para>
    /// </summary>
    internal static (string issuingCountry, string documentCode)? ExtractPolicyFieldsFromDG1(string dg1Base64)
    {
        try
        {
            var dg1Bytes = Convert.FromBase64String(dg1Base64);
            var mrz = ExtractMrzFromDG1(dg1Bytes);
            if (!string.IsNullOrEmpty(mrz) && mrz.Length >= 5)
            {
                var docCode = mrz.Substring(0, 2).Replace("<", "").Trim().ToUpperInvariant();
                var country = mrz.Substring(2, 3).Replace("<", "").Trim().ToUpperInvariant();
                return (country, docCode);
            }
            Console.WriteLine($"[Enclave] DG1'den MRZ okundu ama politika için çok kısa (uzunluk={mrz?.Length ?? 0}).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] Politika alanları DG1'den çıkarılamadı: {ex.Message}");
        }
        return null;
    }

    /// <summary>
    /// Extracts MRZ string from DG1 TLV structure.
    /// DG1 is BER-TLV: Tag 61 { Tag 5F1F { MRZ bytes } }
    /// </summary>
    internal static string ExtractMrzFromDG1(byte[] dg1Bytes)
    {
        try
        {
            var reader = new System.Formats.Asn1.AsnReader(dg1Bytes, System.Formats.Asn1.AsnEncodingRules.BER);
            var outerTag = reader.PeekTag();
            
            // Expected DG1 Wrapper: Application Tag 1 (0x61)
            if (outerTag.TagClass == System.Formats.Asn1.TagClass.Application && outerTag.TagValue == 1 && outerTag.IsConstructed)
            {
                var dg1Reader = reader.ReadSequence(outerTag);
                while (dg1Reader.HasData)
                {
                    var innerTag = dg1Reader.PeekTag();
                    // MRZ Content: Application Tag 31 (0x5F1F)
                    if (innerTag.TagClass == System.Formats.Asn1.TagClass.Application && innerTag.TagValue == 31)
                    {
                        var mrzTagContent = dg1Reader.ReadEncodedValue();
                        
                        // Extract just the inner value (ignoring the 5F 1F XX header bytes)
                        System.Formats.Asn1.AsnDecoder.ReadEncodedValue(
                            mrzTagContent.Span,
                            System.Formats.Asn1.AsnEncodingRules.BER,
                            out int contentOffset,
                            out int contentLength,
                            out int bytesConsumed);
                            
                        return Encoding.ASCII.GetString(mrzTagContent.Span.Slice(contentOffset, contentLength).ToArray());
                    }
                    else
                    {
                        dg1Reader.ReadEncodedValue(); // Skip unknown/optional inner tags
                    }
                }
            }
            throw new Exception("Application Tag 0x61 or 0x5F1F missing in DG1 strict ASN.1 structure.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Enclave] DG1 için ASN.1 ayrıştırma hatası: {ex.Message}. Regex ham çözmeye geçiliyor.");
            // Ultimate Substring Fallback for Malformed/Debug cases
            var raw = Encoding.ASCII.GetString(dg1Bytes);
            // ICAO MRZ is either 88 or 90 characters, containing only A-Z, 0-9, and <
            var match = System.Text.RegularExpressions.Regex.Match(raw, @"[A-Z0-9<]{88,90}");
            if (match.Success)
            {
                Console.WriteLine($"[Enclave] DG1 Yedek: Regex {match.Length} karakterlik MRZ başarıyla çıkardı.");
                return match.Value;
            }
            if (raw.Trim().Length >= 88)
            {
                return raw.Trim(); 
            }
            throw new Exception($"Could not extract MRZ from DG1 using ASN.1 strict parser or Regex fallback: {ex.Message}");
        }
    }

    /// <summary>
    /// Parses MRZ date (YYMMDD) to DateTime.
    /// For DOB: YY > 30 -> 19xx, else 20xx
    /// For Expiry: always 20xx
    /// </summary>
    internal static DateTime ParseMrzDate(string yymmdd, bool isExpiry = false)
    {
        if (yymmdd.Length != 6) return DateTime.MinValue;
        
        int yy = int.Parse(yymmdd.Substring(0, 2));
        int mm = int.Parse(yymmdd.Substring(2, 2));
        int dd = int.Parse(yymmdd.Substring(4, 2));

        if (mm < 1 || mm > 12) mm = 1;
        if (dd < 1 || dd > 31) dd = 1;

        int year;
        if (isExpiry)
        {
            year = 2000 + yy; // Expiry dates are always in 2000s
        }
        else
        {
            year = yy > 30 ? 1900 + yy : 2000 + yy; // DOB heuristic
        }

        try { return new DateTime(year, mm, dd); }
        catch { return DateTime.MinValue; }
    }
}
