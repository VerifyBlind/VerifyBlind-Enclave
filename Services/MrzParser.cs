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

        // TD1 = 90 chars (3×30), TD3 (Passport) = 88 chars (2×44)
        string line1, line2, line3;
        string docNo, nationality, dob, gender, expiry, surname, givenName, issuingCountry;
        string docType = "";

        if (mrzString.Length >= 90)
        {
            // TD1 format (ID Card): 3 lines × 30 chars
            line1 = mrzString.Substring(0, 30);

            // Belge tipi doğrulaması: P (pasaport), I/A/C (kimlik kartı) kabul edilir
            // V (vize) ve diğer geçici belge tipleri reddedilir
            var docTypeChar = line1[0];
            if (docTypeChar != 'P' && docTypeChar != 'I' && docTypeChar != 'A' && docTypeChar != 'C')
                throw new Exception($"Bu belge türü desteklenmemektedir ('{docTypeChar}'). Yalnızca pasaport ve vatandaşlık kimlik kartları kabul edilmektedir.");
            docType = docTypeChar.ToString();

            line2 = mrzString.Substring(30, 30);
            line3 = mrzString.Substring(60, 30);

            issuingCountry = line1.Substring(2, 3).Replace("<", "").Trim();
            docNo = line1.Substring(5, 9).Replace("<", "").Trim();
            dob = line2.Substring(0, 6);
            gender = line2.Substring(7, 1);
            expiry = line2.Substring(8, 6);
            nationality = line2.Substring(15, 3).Replace("<", "").Trim();

            // Line 3: SURNAME<<GIVENNAMES<<<...
            var nameParts = line3.Replace("<", " ").Trim().Split(new[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
            surname = nameParts.Length > 0 ? nameParts[0].Trim() : "";
            givenName = nameParts.Length > 1 ? nameParts[1].Trim() : "";
        }
        else if (mrzString.Length >= 88)
        {
            // TD3 format (Passport): 2 lines × 44 chars
            line1 = mrzString.Substring(0, 44);

            // TD3'te de belge tipi kontrolü (visa TD3 teorik olarak mümkün)
            var docTypeChar = line1[0];
            if (docTypeChar != 'P' && docTypeChar != 'I' && docTypeChar != 'A' && docTypeChar != 'C')
                throw new Exception($"Bu belge türü desteklenmemektedir ('{docTypeChar}'). Yalnızca pasaport ve vatandaşlık kimlik kartları kabul edilmektedir.");
            docType = docTypeChar.ToString();

            line2 = mrzString.Substring(44, 44);

            issuingCountry = line1.Substring(2, 3).Replace("<", "").Trim();
            // Line 1: [DocType1][Type1][Country3][NAME39]
            var nameSection = line1.Substring(5).Replace("<", " ").Trim();
            var nameParts = nameSection.Split(new[] { "  " }, StringSplitOptions.RemoveEmptyEntries);
            surname = nameParts.Length > 0 ? nameParts[0].Trim() : "";
            givenName = nameParts.Length > 1 ? nameParts[1].Trim() : "";

            // Line 2: [DocNo9][Check1][Nationality3][DOB6][Check1][Sex1][Expiry6][Check1]...
            docNo = line2.Substring(0, 9).Replace("<", "").Trim();
            nationality = line2.Substring(10, 3).Replace("<", "").Trim();
            dob = line2.Substring(13, 6);
            gender = line2.Substring(20, 1);
            expiry = line2.Substring(21, 6);
        }
        else
        {
            throw new Exception($"Invalid MRZ length: {mrzString.Length}. Expected 90 (TD1) or 88 (TD3).");
        }

        Console.WriteLine($"[Enclave] DG1 Ayrıştırıldı: Ülke={issuingCountry}, Uyruk={nationality}, BelgeNo={EnclaveService.Mask(docNo)}, Cinsiyet={gender}");

        // Parse DOB (YYMMDD -> DateTime)
        var dobDate = ParseMrzDate(dob);
        var expiryDate = ParseMrzDate(expiry, isExpiry: true);

// For citizens of known countries, we extract their National ID (TCKN for TUR, National ID for THA, etc.)
        // This is stored in different places depending on document type (TD1 vs TD3)
        string primaryId = ""; // Default to empty string (will result in empty person_id/user_id)
        
        bool isTur = issuingCountry == "TUR" || nationality == "TUR";
        bool isTha = issuingCountry == "THA" || nationality == "THA";

        if (isTur || isTha)
        {
            if (mrzString.Length >= 90)
            {
                // TD1 (ID Card): Optional Data field (Line 1, index 15-29)
                var optionalData = line1!.Substring(15, 15).Replace("<", "").Trim();
                if (isTur && optionalData.Length >= 11 && optionalData.Take(11).All(char.IsDigit))
                {
                    primaryId = optionalData.Substring(0, 11);
                    Console.WriteLine($"[Enclave] TD1 İsteğe Bağlı Veriden TCKN çıkarıldı: {EnclaveService.Mask(primaryId)}");
                }
                // (Thailand TD1 support can be added here if needed)
            }
            else if (mrzString.Length >= 88)
            {
                // TD3 (Passport): Personal Number (Line 2, positions 28-42 in zero-based Line 2 index)
                // Total mrzString index: 44 + 28 = 72. Length: 14.
                if (mrzString.Length >= 72 + 14)
                {
                    var personalNo = mrzString.Substring(72, 14).Replace("<", "").Trim();
                    
                    if (isTha && personalNo.Length >= 13 && personalNo.Take(13).All(char.IsDigit))
                    {
                        primaryId = personalNo.Substring(0, 13);
                        Console.WriteLine($"[Enclave] TD3 Kişisel Numaradan Tayland Ulusal ID çıkarıldı: {EnclaveService.Mask(primaryId)}");
                    }
                    else if (isTur && personalNo.Length >= 11 && personalNo.Take(11).All(char.IsDigit))
                    {
                        primaryId = personalNo.Substring(0, 11);
                        Console.WriteLine($"[Enclave] TD3 Kişisel Numaradan TCKN çıkarıldı: {EnclaveService.Mask(primaryId)}");
                    }
                    else if (isTur || isTha)
                    {
                        Console.WriteLine($"[Enclave] UYARI: {issuingCountry}/{nationality} belgesi tespit edildi ancak Kişisel Numara alanı geçersiz veya ID eksik: '{EnclaveService.Mask(personalNo)}'");
                    }
                } 
            }
        }

        return new TicketPayload
        {
TCKN = primaryId, // Will be empty for non-TUR or missing TCKN
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
