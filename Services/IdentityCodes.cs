using System.Security.Cryptography;
using System.Text;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Partner'a dönen tekillik kodlarının türetimi: <c>nsbd_id</c> ve <c>doc_id</c>. İkisi de
/// partner-scoped'tır (partner'lar arası eşleştirme/unlinkability korunur) ve login-zamanında
/// ticket alanlarından üretilir; <c>user_id</c> ile aynı KMS-HMAC kalıbını izler.
///
/// <para><b>nsbd_id</b>: TCKN olmayan kimlikler için biyografik "kişi kovası". Bir kişinin tüm
/// kartlarında sabit kalmalı (aynı kişi farklı kartlarla tekrar kayıt → aynı nsbd_id), bu yüzden
/// HMAC girdisi BAYT-BAYT deterministik olmak zorunda. Olasılıksal bir ipucudur (namesake çakışması
/// + isim değişimi kayması olabilir), otoriter bir tekillik anahtarı DEĞİLDİR.</para>
///
/// <para><b>doc_id</b>: partner-scoped <c>card_id</c> (SOD-tabanlı). Aynı doc_id ⟹ aynı fiziksel
/// belge ⟹ aynı kişi (sert sinyal). SOD-tabanlı olduğu için kanonikleştirme gerekmez.</para>
///
/// nsbd_id girdileri MRZ/DG1 kaynaklı (zaten BÜYÜK harf, A-Z'ye transliterasyon, '&lt;'→boşluk —
/// bkz MrzParser). Yine de savunmacı kanonikleştiriyoruz: olası non-ASCII (gelecekte DG11 / demo
/// verisi) deterministik biçimde elensin diye sadece [A-Z] (+ isimlerde boşluk) tutulur.
/// </summary>
public static class IdentityCodes
{
    /// <summary>
    /// nsbd_id kanonik girdi şeması sürümü. Reçete (alan kaynağı/normalizasyon) ileride değişirse
    /// "NSBD2"ye yükseltilir; eski/yeni kodlar yapısal olarak ayrışır ve geçiş penceresinde ikisi de
    /// üretilebilir. doc_id SOD-tabanlı olduğu için sürüm gerektirmez.
    /// </summary>
    public const string NsbdVersion = "NSBD1";

    /// <summary>
    /// TCKN format kapısı: tam 11 hane, tamamı rakam, ilk hane 0 olamaz.
    ///
    /// <para><b>Neden var:</b> daha önce yalnız "boş mu" kontrol ediliyordu. MRZ'nin İsteğe Bağlı
    /// Veri alanı beklenenden farklı geldiğinde (ör. alan boş ya da başka veri taşıyor) sistem
    /// sessizce boş TCKN ile devam ediyor, login'de partner'a <c>user_id = ""</c> dönüyordu —
    /// yani TCKN'siz TÜM kullanıcılar partner tarafında AYNI kimliğe çakışıyordu. Artık geçersiz
    /// TCKN'de kod hiç üretilmez ve alan cevaptan düşer.</para>
    ///
    /// <para>Kasıtlı olarak TCKN'nin doğrulama-hanesi (checksum) algoritması UYGULANMAZ: buradaki
    /// amaç "çöp değer üretme"yi engellemektir, vatandaşlık numarasının gerçekliğine hükmetmek
    /// değil. Checksum eklemek gerçek bir kartı yanlışlıkla reddetme riski taşır; asıl güvence
    /// zaten SOD/CSCA zinciridir.</para>
    /// </summary>
    public static bool IsValidTckn(string? tckn) =>
        !string.IsNullOrEmpty(tckn) && tckn.Length == 11 && tckn[0] != '0' && tckn.All(char.IsDigit);

    /// <summary>
    /// nsbd_id üretir: <c>hex(SHA256(HMAC( BuildNsbdCanonical(payload) + ":" + partnerId )))</c>.
    /// Güvenilir bir kod üretilemiyorsa (kanonik boş ya da partnerId boş) <c>null</c> döner.
    /// </summary>
    public static async Task<string?> BuildNsbdIdAsync(IKmsService kms, TicketPayload payload, string partnerId)
    {
        if (string.IsNullOrEmpty(partnerId)) return null;
        var canon = BuildNsbdCanonical(payload);
        if (string.IsNullOrEmpty(canon)) return null;

        // ":" + partnerId scope eki user_id ile birebir aynı kalıp; kanonik string MRZ alfabesinde
        // ":" içermez → ayraç güvenli.
        var hmac = await kms.ComputeHmacAsync($"{canon}:{partnerId}");
        return Sha256Hex(hmac);
    }

    /// <summary>
    /// doc_id üretir: <c>"{DocType}_" + hex(SHA256(HMAC( cardId + ":" + partnerId )))</c>.
    /// cardId (SOD-tabanlı global belge kodu) ticket'tan gelir. cardId ya da partnerId boşsa
    /// <c>null</c> döner. DocType yoksa "X" kullanılır.
    /// </summary>
    public static async Task<string?> BuildDocIdAsync(IKmsService kms, string cardId, string? documentType, string partnerId)
    {
        if (string.IsNullOrEmpty(cardId) || string.IsNullOrEmpty(partnerId)) return null;

        var hmac = await kms.ComputeHmacAsync($"{cardId}:{partnerId}");
        var docType = string.IsNullOrEmpty(documentType) ? "X" : documentType;
        return $"{docType}_{Sha256Hex(hmac)}";
    }

    /// <summary>
    /// nsbd_id için HMAC'lenecek kanonik string: "NSBD1|{UYRUK}|{SOYAD}|{AD}|{YYYYMMDD}|{CINSIYET}".
    /// Güvenilir bir kod üretilemiyorsa (uyruk+ülke boş, ad+soyad boş, ya da doğum tarihi geçersiz)
    /// boş string döner → çağıran taraf nsbd_id üretmemeli.
    /// </summary>
    public static string BuildNsbdCanonical(TicketPayload payload)
    {
        // Uyruk yoksa ihraç eden ülkeye düş; ikisi de yoksa kod üretme.
        var nationality = KeepUpperAlpha(payload.Uyruk);
        // Uyruk boşsa boş dönsün, çağıran taraf nsbd_id üretmesin diye.
        //if (nationality.Length == 0)
        //    nationality = KeepUpperAlpha(payload.CountryIsoCode);
        if (nationality.Length == 0)
            return string.Empty;

        var surname = NormalizeName(payload.Soyad);
        var given = NormalizeName(payload.Ad);
        if (surname.Length == 0 && given.Length == 0)
            return string.Empty;

        // Doğum tarihi MrzParser'da parse edilemezse DateTime.MinValue olur → güvenilmez, kod üretme.
        if (payload.DogumTarihi == DateTime.MinValue)
            return string.Empty;
        var dob = payload.DogumTarihi.ToString("yyyyMMdd");

        // Cinsiyet MrzParser'da M/F/< olarak gelir; M/F dışındaki her şey (<, X, boş) tek "X"
        // token'ına eşlenir → belirtilmemiş cinsiyetli kişiler de nsbd_id (dolayısıyla süreklilik) alır.
        var gender = payload.Cinsiyet == "M" || payload.Cinsiyet == "F" ? payload.Cinsiyet! : "X";

        return string.Join("_", NsbdVersion, nationality, surname, given, dob, gender);
    }

    private static string Sha256Hex(string base64Hmac) =>
        Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(base64Hmac))).ToLowerInvariant();

    /// <summary>Büyük harfe çevirir, yalnız A-Z karakterlerini tutar (deterministik elemeli).</summary>
    private static string KeepUpperAlpha(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sb = new StringBuilder(value.Length);
        foreach (var c in value.ToUpperInvariant())
            if (c >= 'A' && c <= 'Z') sb.Append(c);
        return sb.ToString();
    }

    /// <summary>
    /// İsim normalizasyonu: büyük harf → yalnız [A-Z] ve boşluk → ardışık boşlukları tek boşluğa indir → trim.
    /// </summary>
    private static string NormalizeName(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var sb = new StringBuilder(value.Length);
        bool pendingSpace = false;
        foreach (var c in value.ToUpperInvariant())
        {
            if (c >= 'A' && c <= 'Z')
            {
                if (pendingSpace && sb.Length > 0) sb.Append(' ');
                pendingSpace = false;
                sb.Append(c);
            }
            else if (c == ' ')
            {
                pendingSpace = true;
            }
            // diğer her şey (rakam, noktalama, non-ASCII) atılır
        }
        return sb.ToString();
    }
}
