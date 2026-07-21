namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Hangi belgelerin kabul edildiğine dair TEK karar noktası (enclave tarafı güven sınırı).
/// Mobil taraftaki <c>DocumentSupport</c> (Android <c>nfc/DocumentSupport.kt</c>, iOS
/// <c>NFC/DocumentSupport.swift</c>) aynı kuralı kullanıcıya erken mesaj göstermek için
/// tekrarlar; BURASI ise otorite — değiştirilmiş bir istemci mobil kapıyı atlayabilir.
///
/// <para><b>Kural:</b> ihraç eden ülke <c>TUR</c> ve ICAO belge kodu <c>I</c> ya da <c>ID</c>.
/// Yani yalnızca Türkiye Cumhuriyeti kimlik kartı. Türk pasaportu (<c>P</c>) da dahil olmak
/// üzere diğer her belge reddedilir.</para>
///
/// <para><b>Pasaport neden kapalı:</b> pasaport DG2'si JPEG2000 olabilir (ne mobil ne enclave
/// çözebilir) ve Active Authentication yerine yalnız Chip Authentication kullanıyor olabilir.
/// İkisi de gerçek bir Türk pasaportuyla test edilmeden açılmamalı. Açılırken burada
/// <c>AcceptedDocumentCodes</c>'a "P" eklemek YETMEZ — JP2 decode ve AA politikası da
/// çözülmeli.</para>
///
/// <para><b>Çağrı sırası şartı:</b> yalnızca Passive Authentication DG1'i SOD'a karşı
/// doğruladıktan SONRA çağrılmalı. Doğrulanmamış DG1 üzerinde çalışırsa saldırgan ülke alanına
/// "TUR" yazıp kapıyı geçer.</para>
/// </summary>
public static class DocumentPolicy
{
    /// <summary>Kabul edilen tek ihraç ülkesi (ICAO 3-harf kodu).</summary>
    public const string AcceptedCountry = "TUR";

    /// <summary>
    /// Kabul edilen ICAO belge kodları. TD1 kimlik kartlarında MRZ satır 1 "I&lt;TUR.." ise kod
    /// "I", "IDTUR.." ise "ID" olur — ikisi de aynı fiziksel belgedir (üretim yılına göre değişir).
    /// </summary>
    public static readonly string[] AcceptedDocumentCodes = { "I", "ID" };

    public enum Verdict
    {
        /// <summary>TC kimlik kartı — akışa devam edilebilir.</summary>
        Accepted,
        /// <summary>İhraç eden ülke Türkiye değil.</summary>
        UnsupportedCountry,
        /// <summary>Ülke Türkiye ama belge kimlik kartı değil (ör. pasaport).</summary>
        UnsupportedDocumentType
    }

    /// <summary>
    /// Belgeyi değerlendirir. Ülke kontrolü belge tipinden ÖNCE gelir: yabancı bir pasaportta
    /// "pasaport desteklenmiyor" demek yanıltıcı olurdu (pasaportu Türk olsa da kabul edilmezdi
    /// demeye gelir), doğru mesaj "yalnızca TC kimlik kartı"dır.
    /// </summary>
    public static Verdict Evaluate(string? issuingCountry, string? documentCode)
    {
        if (!string.Equals(Normalize(issuingCountry), AcceptedCountry, StringComparison.Ordinal))
            return Verdict.UnsupportedCountry;

        var code = Normalize(documentCode);
        if (Array.IndexOf(AcceptedDocumentCodes, code) < 0)
            return Verdict.UnsupportedDocumentType;

        return Verdict.Accepted;
    }

    /// <summary>Verdict → EnclaveErrorCodes sabiti. Accepted için null.</summary>
    public static string? ErrorCodeFor(Verdict verdict) => verdict switch
    {
        Verdict.UnsupportedCountry      => VerifyBlind.Core.EnclaveErrorCodes.UnsupportedCountry,
        Verdict.UnsupportedDocumentType => VerifyBlind.Core.EnclaveErrorCodes.UnsupportedDocType,
        _                               => null
    };

    /// <summary>
    /// MRZ alanlarını karşılaştırmaya hazırlar: büyük harf, ICAO dolgu karakteri '&lt;' ve boşluk
    /// atılır. MRZ zaten büyük harf A-Z'dir; bu savunmacı normalizasyon DG1 ayrıştırıcısının
    /// dolgu bırakması ya da mobil tarafın farklı kırpma yapması hâlinde kararı değiştirmez.
    /// </summary>
    private static string Normalize(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : value.Replace("<", "").Trim().ToUpperInvariant();
}
