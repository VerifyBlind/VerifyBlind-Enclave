using System.Globalization;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services.UniqueCount;

/// <summary>Sorgu reddi — controller 400'e çevirir. Kod istemciye gider, kişisel veri içermez.</summary>
public sealed class CountQueryException(string errorCode) : Exception(errorCode)
{
    public string ErrorCode { get; } = errorCode;
}

/// <summary>
/// Tekil sayım deposu (spec: docs/superpowers/specs/2026-11-09-unique-count-store-design.md).
/// Gün başına kod kümeleri RAM'de; dışarı yalnız KAPANMIŞ günlerin sayıları çıkar.
///
/// ⚠️ Kodlar hiçbir log'a, cevaba, hata mesajına yazılmaz.
/// ⚠️ "Bugün" enclave'in KENDİ saatinden hesaplanır, RelayClock'tan değil: relay saati yalnız ileri
/// taşıyabilir; ileri alınmış bir saat bugünü "kapanmış" gösterip yeni-kişi bitini sızdırırdı.
/// ⚠️ Yüklenmeden kaydetme YOK: yeniden başlayan enclave boş durumu eski blob'un üstüne yazmasın.
/// Yükleme, o ana kadar RAM'de birikenle BİRLEŞTİRİLİR (doğrulama hiçbir zaman yüklemeyi beklemez).
/// </summary>
public sealed class UniqueCountStore
{
    public static readonly TimeSpan TurkeyOffset = TimeSpan.FromHours(3);
    public const int RetentionYears = 10;
    private const long WarnEntryCount = 5_000_000;

    private readonly object _gate = new();
    private readonly Dictionary<SetKey, Dictionary<DateOnly, HashSet<ulong>>> _sets = new();
    private readonly Dictionary<string, long> _versions = new();
    private readonly HashSet<string> _dirtyMonths = new();
    private readonly IIdentityHmacService _hmac;
    private readonly Func<DateTime> _utcNow;
    private bool _loaded;
    private long _entryCount;
    private bool _warned;

    public UniqueCountStore(IIdentityHmacService hmac, Func<DateTime>? utcNow = null)
    {
        _hmac = hmac;
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public DateOnly Today() => DateOnly.FromDateTime(_utcNow() + TurkeyOffset);

    public bool IsLoaded { get { lock (_gate) return _loaded; } }

    // ── Kayıt ────────────────────────────────────────────────────────────────

    public void RecordLogin(string tckn, string partnerId)
    {
        if (!IdentityCodes.IsValidTckn(tckn) || tckn == EnclaveService.DemoTckn || string.IsNullOrWhiteSpace(partnerId)) return;
        var day = Today();
        var person = CountCodes.Person(_hmac, tckn);
        var partnerPerson = CountCodes.PartnerPerson(_hmac, tckn, partnerId);
        lock (_gate)
        {
            Add(new SetKey(CountFamilies.PersonLogin, null), day, person, markDirty: true);
            Add(new SetKey(CountFamilies.PartnerPerson, CountCodes.NormalizePartner(partnerId)), day, partnerPerson, markDirty: true);
        }
    }

    public void RecordRegister(string? tckn, string sodHashHex)
    {
        if (string.IsNullOrEmpty(sodHashHex) || tckn == EnclaveService.DemoTckn) return;
        var day = Today();
        var card = CountCodes.Card(_hmac, sodHashHex);
        ulong? person = IdentityCodes.IsValidTckn(tckn) ? CountCodes.Person(_hmac, tckn!) : null;
        lock (_gate)
        {
            Add(new SetKey(CountFamilies.Card, null), day, card, markDirty: true);
            if (person is ulong p) Add(new SetKey(CountFamilies.PersonRegister, null), day, p, markDirty: true);
        }
    }

    // ── Sorgu (yalnız kapanmış günler) ──────────────────────────────────────

    public int Query(string family, string? partnerId, DateOnly from, DateOnly to)
    {
        var key = KeyFor(family, partnerId);
        if (from > to) throw new CountQueryException("ERR_COUNT_RANGE_INVALID");
        lock (_gate)
        {
            EnsureReadable(to);
            if (!_sets.TryGetValue(key, out var days)) return 0;
            var union = new HashSet<ulong>();
            foreach (var (day, codes) in days)
                if (day >= from && day <= to) union.UnionWith(codes);
            return union.Count;
        }
    }

    public List<CountStoreDailyTotal> Daily(DateOnly day)
    {
        lock (_gate)
        {
            EnsureReadable(day);
            var totals = new List<CountStoreDailyTotal>();
            foreach (var (key, days) in _sets)
                if (days.TryGetValue(day, out var codes) && codes.Count > 0)
                    totals.Add(new CountStoreDailyTotal { Family = key.Family, PartnerId = key.PartnerId, DistinctCount = codes.Count });
            return totals;
        }
    }

    // ── Kalıcılık ────────────────────────────────────────────────────────────

    public CountStoreSaveResponse Save()
    {
        lock (_gate)
        {
            if (!_loaded) return new CountStoreSaveResponse { Status = CountStoreSaveResponse.StatusNotLoaded };

            TrimExpired();
            var key = BlobKey();
            var months = new SortedSet<string>(_dirtyMonths, StringComparer.Ordinal) { MonthKey(Today()), MonthKey(Today().AddMonths(-1)) };
            var response = new CountStoreSaveResponse { Status = CountStoreSaveResponse.StatusOk };
            foreach (var month in months)
            {
                var version = (_versions.TryGetValue(month, out var v) ? v : 0) + 1;
                _versions[month] = version;
                response.Blobs.Add(new CountStoreBlob
                {
                    Month = month,
                    Version = version,
                    Blob = CountStoreBlobCodec.Encrypt(key, month, version, SnapshotMonth(month)),
                });
            }
            _dirtyMonths.Clear();
            return response;
        }
    }

    public void Load(IReadOnlyList<CountStoreBlob> blobs)
    {
        var key = BlobKey();
        // Önce HEPSİ çözülür: bozuk bir blob varsa hiçbir şey birleştirilmez, depo yüklenmemiş kalır.
        var decoded = blobs.Select(b => (Blob: b, Entries: CountStoreBlobCodec.Decrypt(key, b.Month, b.Version, b.Blob))).ToList();
        lock (_gate)
        {
            foreach (var (blob, entries) in decoded)
            {
                foreach (var e in entries)
                    foreach (var code in e.Codes)
                        Add(e.Key, e.Day, code, markDirty: false);
                _versions[blob.Month] = Math.Max(_versions.TryGetValue(blob.Month, out var v) ? v : 0, blob.Version);
            }
            _loaded = true;
        }
        Console.WriteLine($"[UniqueCount] Depo yüklendi ({decoded.Count} ay).");
    }

    // ── İç ───────────────────────────────────────────────────────────────────

    /// <summary>Blob anahtarı: kimlik HMAC'inin sabit girdiye çıktısı (32 bayt). Sır servisten çıkmaz.</summary>
    private byte[] BlobKey() => Convert.FromBase64String(_hmac.ComputeHmac("vb-count-store-key-v1"));

    private static SetKey KeyFor(string family, string? partnerId)
    {
        if (!CountFamilies.All.Contains(family)) throw new CountQueryException("ERR_COUNT_FAMILY_INVALID");
        var needsPartner = family == CountFamilies.PartnerPerson;
        if (needsPartner == string.IsNullOrWhiteSpace(partnerId)) throw new CountQueryException("ERR_COUNT_PARTNER_INVALID");
        return new SetKey(family, needsPartner ? CountCodes.NormalizePartner(partnerId!) : null);
    }

    private void EnsureReadable(DateOnly lastDay)
    {
        if (!_loaded) throw new CountQueryException("ERR_COUNT_NOT_LOADED");
        if (lastDay >= Today()) throw new CountQueryException("ERR_COUNT_DAY_NOT_CLOSED");
    }

    private void Add(SetKey key, DateOnly day, ulong code, bool markDirty)
    {
        if (!_sets.TryGetValue(key, out var days)) _sets[key] = days = new Dictionary<DateOnly, HashSet<ulong>>();
        if (!days.TryGetValue(day, out var codes)) days[day] = codes = new HashSet<ulong>();
        if (!codes.Add(code)) return;

        _entryCount++;
        if (markDirty) _dirtyMonths.Add(MonthKey(day));
        if (!_warned && _entryCount > WarnEntryCount)
        {
            _warned = true;
            Console.WriteLine($"[UniqueCount] UYARI: depo {_entryCount} kaydı aştı — bellek ve blob boyutu izlenmeli.");
        }
    }

    private List<CountStoreBlobCodec.Entry> SnapshotMonth(string month)
    {
        var list = new List<CountStoreBlobCodec.Entry>();
        foreach (var (key, days) in _sets)
            foreach (var (day, codes) in days)
            {
                if (codes.Count == 0 || MonthKey(day) != month) continue;
                var arr = codes.ToArray();
                Array.Sort(arr);
                list.Add(new CountStoreBlobCodec.Entry(key, day, arr));
            }
        return list;
    }

    private void TrimExpired()
    {
        var cutoff = Today().AddYears(-RetentionYears);
        foreach (var key in _sets.Keys.ToList())
        {
            var days = _sets[key];
            foreach (var day in days.Keys.Where(d => d < cutoff).ToList())
            {
                _entryCount -= days[day].Count;
                days.Remove(day);
            }
            if (days.Count == 0) _sets.Remove(key);
        }
    }

    private static string MonthKey(DateOnly day) => day.ToString("yyyy-MM", CultureInfo.InvariantCulture);
}
