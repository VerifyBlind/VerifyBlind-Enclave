namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Asgari yaş kapısı — enclave tarafı OTORİTE. Kullanım Şartları "on beş yaşını doldurmamış
/// kullanıcılar" hizmet kapsamı dışında der.
///
/// <para><b>Neden burada da var:</b> mobil taraf (<c>AgePolicy.kt</c> / <c>AgePolicy.swift</c>)
/// aynı kuralı kullanıcıya erken ve net mesaj göstermek için uygular, ama değiştirilmiş bir
/// istemci o kapıyı atlayabilir. Ayrıca mobil taraf ayrıştırılamayan MRZ'de bilinçli olarak
/// fail-open davranır (bozuk okuma yüzünden meşru kullanıcı kilitlenmesin) — bu da kararı
/// buraya bırakır.</para>
///
/// <para><b>Neden <see cref="DocumentPolicy"/>'den ayrı:</b> DocumentPolicy belgenin teknik
/// olarak işlenebilir olup olmadığına bakar (ülke, belge tipi). Yaş ise bir politika kararıdır —
/// belge kusursuz okunur, kayıt yine de reddedilir. Sınır 15'ten 18'e çekilirse teknik kapı
/// kurcalanmasın diye ayrık tutulur.</para>
///
/// <para><b>Çağrı sırası şartı:</b> yalnızca Passive Authentication DG1'i SOD'a karşı
/// doğruladıktan SONRA çağrılmalı. Doğrulanmamış DG1 üzerinde çalışırsa saldırgan doğum tarihi
/// alanını değiştirip kapıyı geçer.</para>
/// </summary>
public static class AgePolicy
{
    /// <summary>Hizmetin açık olduğu en küçük yaş. Kullanım Şartları'ndaki ifadeyle hizalı.</summary>
    public const int MinimumAge = 15;

    public enum Verdict
    {
        /// <summary>Yaş sınırı karşılanıyor.</summary>
        Accepted,
        /// <summary>Kullanıcı <see cref="MinimumAge"/> yaşını doldurmamış → kayıt reddedilir.</summary>
        BelowMinimumAge,
        /// <summary>Doğum tarihi MRZ'den çözülemedi — çağıran ERR_DG1_PARSE'a eşler.</summary>
        Unparseable
    }

    /// <summary>
    /// MRZ'nin <c>YYMMDD</c> doğum tarihini değerlendirir.
    /// </summary>
    /// <param name="mrzDateOfBirth">ICAO MRZ doğum tarihi alanı (6 hane).</param>
    /// <param name="today">Testlerde sabitlenebilsin diye dışarıdan verilir.</param>
    public static Verdict Evaluate(string? mrzDateOfBirth, DateTime? today = null)
    {
        // Enclave saati UTC'dir; yerel saat dilimi kararı kaydırmamalı.
        var now = (today ?? DateTime.UtcNow).Date;
        var birthDate = ParseMrzDate(mrzDateOfBirth, now);
        if (birthDate == null) return Verdict.Unparseable;

        return AgeOn(birthDate.Value, now) < MinimumAge
            ? Verdict.BelowMinimumAge
            : Verdict.Accepted;
    }

    /// <summary>
    /// MRZ <c>YYMMDD</c> → tarih. Ayrıştırılamazsa null.
    ///
    /// <para><b>Yüzyıl kuralı:</b> MRZ yılı 2 hanedir, yani "30" hem 1930 hem 2030 olabilir.
    /// Doğum tarihi geçmişte olmak zorunda olduğundan 2000'li yüzyıl varsayılır; sonuç bugünden
    /// İLERİDEYSE 1900'e düşülür. Böylece 2026'da "27" → 1927, "10" → 2010 olur.</para>
    /// </summary>
    private static DateTime? ParseMrzDate(string? value, DateTime today)
    {
        var digits = (value ?? string.Empty).Replace("<", "").Trim();
        if (digits.Length != 6 || !digits.All(char.IsDigit)) return null;

        if (!int.TryParse(digits.Substring(0, 2), out var yy)) return null;
        if (!int.TryParse(digits.Substring(2, 2), out var mm)) return null;
        if (!int.TryParse(digits.Substring(4, 2), out var dd)) return null;

        var candidate = MakeDate(2000 + yy, mm, dd);
        if (candidate == null) return null;
        // Gelecekteki bir "doğum tarihi" olamaz → aynı 2 haneli yıl 1900'lü yüzyılda okunur.
        return candidate.Value > today ? MakeDate(1900 + yy, mm, dd) : candidate;
    }

    /// <summary>Geçersiz ay/gün (ör. 13. ay, 32. gün) sessizce kaydırılmasın diye kontrollü kurulum.</summary>
    private static DateTime? MakeDate(int year, int month, int day)
    {
        if (month < 1 || month > 12) return null;
        if (year < 1 || year > 9999) return null;
        if (day < 1 || day > DateTime.DaysInMonth(year, month)) return null;
        return new DateTime(year, month, day);
    }

    /// <summary>
    /// Tam yıl cinsinden yaş. Doğum günü henüz gelmediyse bir eksiltir — "15 yaşını doldurmuş
    /// olmak" ifadesinin karşılığı budur.
    /// </summary>
    private static int AgeOn(DateTime birthDate, DateTime today)
    {
        var age = today.Year - birthDate.Year;
        if (today.Month < birthDate.Month ||
            (today.Month == birthDate.Month && today.Day < birthDate.Day))
        {
            age--;
        }
        return age;
    }
}
