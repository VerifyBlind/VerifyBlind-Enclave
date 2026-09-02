namespace VerifyBlind.Enclave.Services;

/// <summary>
/// RegisterAsync akışında belirli bir adımda oluşan hatayı temsil eder.
/// Message → JSON {"code":"ERR_XXX","step":"...","detail":"..."} döner.
/// API katmanı code'u SharedResources üzerinden lokalize eder.
/// </summary>
public class RegistrationException : Exception
{
    public RegistrationStep Step { get; }
    public string ErrorCode { get; }
    public string? TechnicalDetail { get; }
    /// <summary>Biyometrik red durumunda skoru taşır (relay metriği için, ZK-güvenli skaler). Diğer hatalarda null.</summary>
    public float? FaceScore { get; init; }

    /// <summary>
    /// Belge politikası reddinde SOD-doğrulanmış ihraç eden ülke kodu (ör. "DEU"). Relay bunu
    /// Sentry'ye yapısal alan olarak basar — istemcinin beyan ettiği CountryIsoCode'dan farklı
    /// olarak GÜVENİLİRDİR. ZK-güvenli: düşük kardinaliteli ISO kodu, kişisel veri değil.
    /// Diğer hatalarda null.
    /// </summary>
    public string? IssuingCountry { get; init; }

    /// <summary>
    /// YAPISAL teşhis — relay bunu Sentry'ye alan olarak basar. `TechnicalDetail`'in aksine
    /// serbest metin DEĞİLDİR: yalnız sabit formatlı, karta/kişiye bağlanamayan alanlar taşır
    /// (algoritma, anahtar bit uzunluğu, imza/DG uzunlukları, ISO 9796-2 blok başlık+trailer baytı).
    /// Kişisel veri, TCKN, açık anahtar veya imza içeriği ASLA buraya yazılmaz — bunlar kart-özgü
    /// ve dolayısıyla ilişkilendirilebilir olurdu.
    /// </summary>
    public string? Diagnostic { get; init; }

    public RegistrationException(RegistrationStep step, string errorCode, string? technicalDetail = null)
        : base(errorCode)
    {
        Step = step;
        ErrorCode = errorCode;
        TechnicalDetail = technicalDetail;
    }

    public override string Message =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            code   = ErrorCode,
            step   = Step.ToString(),
            detail = TechnicalDetail,
            diag   = Diagnostic
        });
}

/// <summary>
/// Aktif Kimlik Doğrulama reddi — yapısal teşhis profilini taşır.
///
/// Üretim enclave'i debug modda olmadığı için `Console.WriteLine` çıktısı HİÇBİR YERDE görünmez;
/// bir kart AA'dan geçemezse elimizdeki tek kanıt budur. Kartı tekrar isteyemeyeceğimiz için
/// (kullanıcı geri bildirimi 2026-08-21) hangi ISO 9796-2 varyantının kullanıldığını TEK denemede
/// anlayabilmemiz gerekir.
/// </summary>
public class ActiveAuthException : Exception
{
    /// <summary>Yapısal, PII'sız profil (bkz. RegistrationException.Diagnostic).</summary>
    public string? Profile { get; init; }

    public ActiveAuthException(string message) : base(message) { }
}

/// <summary>
/// Pasif Kimlik Doğrulama reddi — yapısal teşhis profilini taşır.
///
/// AA ile aynı gerekçe: üretim enclave'inde Console görünmez ve kartı tekrar isteyemeyiz. Üstelik
/// PA'nın düşme sebepleri birbirinden ÇOK farklı operasyonel sonuçlar doğurur — CSCA deposu eksik
/// (bizim kurulum hatamız), CRL bayat (elle güncellenen paket), DG hash uyuşmazlığı (NFC okuma
/// bozulması), sertifika iptal (gerçek güvenlik olayı). Hangisi olduğunu bilmeden hiçbiri ayırt
/// edilemez. Profil yalnız hangi kontrolün düştüğünü ve yapısal bağlamı taşır.
/// </summary>
public class PassiveAuthException : Exception
{
    /// <summary>Yapısal, PII'sız profil (bkz. RegistrationException.Diagnostic).</summary>
    public string? Profile { get; init; }

    public PassiveAuthException(string message) : base(message) { }
}

/// <summary>
/// Biyometrik eşik-altı reddi. Skoru taşır → red skoru relay metriğine (ZK-güvenli skaler) yansıtılabilir.
/// </summary>
public class BiometricMismatchException : Exception
{
    public float Score { get; }
    public BiometricMismatchException(float score, string message) : base(message) => Score = score;
}

/// <summary>
/// Nonce'un 15 dakikalık tazelik penceresini aşması — kullanıcı MRZ girişi + NFC okuma +
/// canlılık adımlarını süresinde bitirememiştir.
///
/// Nonce imzasının geçersiz olmasından AYRI tutulur: bu bir arıza ya da saldırı işareti değil,
/// beklenen kullanıcı davranışıdır (ilk kez deneyen biri 5 dk 34 sn'de bitirmişti, 2026-08-21).
/// Ayrım relay'e ERR_NONCE_EXPIRED koduyla taşınır; relay bu kodu Sentry'ye event üretmeyen
/// seviyede loglar, imza geçersizliğini ise uyarı olarak bırakır.
/// </summary>
public class NonceExpiredException : InvalidOperationException
{
    /// <summary>Nonce'un reddedildiği andaki yaşı (saniye).</summary>
    public long AgeSeconds { get; }
    /// <summary>İzin verilen tazelik penceresi (saniye).</summary>
    public long MaxAgeSeconds { get; }

    public NonceExpiredException(long ageSeconds, long maxAgeSeconds)
        : base($"Nonce süresi dolmuş: Zaman damgası çok eski ({ageSeconds}s). İzin verilen maksimum: {maxAgeSeconds}s.")
    {
        AgeSeconds    = ageSeconds;
        MaxAgeSeconds = maxAgeSeconds;
    }
}
