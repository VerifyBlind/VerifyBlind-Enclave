using System.Collections.Concurrent;

namespace VerifyBlind.Enclave.Services;

/// <summary>PIN türetme sonucu — "bozuk zarf" ile "kota aşıldı" ayrımı çağırana taşınır.</summary>
public enum PinDeriveStatus
{
    Ok,
    /// <summary>Zarf çözülemedi / eksik alan. İstemciye 400.</summary>
    Invalid,
    /// <summary>Enclave-içi tahmin kotası doldu. İstemciye 429; relay slot İADE ETMEZ.</summary>
    RateLimited
}

public sealed record PinDeriveResult(PinDeriveStatus Status, string? PersonId)
{
    public static readonly PinDeriveResult Invalid = new(PinDeriveStatus.Invalid, null);
    public static readonly PinDeriveResult RateLimited = new(PinDeriveStatus.RateLimited, null);
}

/// <summary>
/// PIN → person_id türetimi için ENCLAVE-İÇİ tahmin sayacı (kaba kuvvet backstop'u).
///
/// <para><b>Neden relay'deki yetmiyor:</b> <c>PinDeriveRateLimiter</c> (Redis, UUID başına 10/gün)
/// relay'de yaşar ve relay bu mimaride GÜVENİLMEYEN bileşendir — TCKN'nin hibrit şifreli geçmesinin
/// sebebi de budur. Ele geçirilmiş bir relay kendi sayacını atlayıp bu ucu dövebilirdi: 6 haneli PIN
/// uzayı (10^6) saniyede birkaç yüz istekle saatler içinde taranırdı. Buradaki sayaç o senaryoda
/// saldırganı yine UUID başına <see cref="_maxPerWindow"/>/gün'e indirir.</para>
///
/// <para><b>Neden güvenilir:</b> anahtar olarak kullanılan uuid, relay'in beyanından DEĞİL, hibrit
/// zarfın İÇİNDEN gelir (<see cref="EnclaveService.DerivePinPersonIdAsync"/>). Zarf olmasaydı
/// ele geçirilmiş relay her tahminde sahte bir uuid göndererek sayacı anlamsızlaştırırdı.</para>
///
/// <para><b>Bilinen sınır — restart'ta sıfırlanır (fail-open):</b> sayaç RAM'dedir; enclave restart'ı
/// (deploy/crash/watchdog) pencereleri siler. Kabul edilmiştir: restart nadirdir ve ele geçirilmiş bir
/// relay enclave'i restart EDEMEZ (o, host erişimi = çok daha büyük bir ihlal demektir). Kalıcı durum
/// tutulmaz — enclave'in durumsuzluğu bilinçli bir tasarım kararıdır.</para>
///
/// <para><b>Bellek sınırı:</b> kötü niyetli bir çağıran milyonlarca farklı uuid göndererek belleği
/// şişirebilir. Süresi dolmuş pencereler periyodik süpürülür; tablo yine de dolarsa YENİ uuid'ler
/// reddedilir (fail-closed). Mevcut sayaçlar TAHLİYE EDİLMEZ — tahliye, saldırganın tabloyu doldurup
/// kurbanın sayacını sıfırlamasına izin verirdi ki bu tam da engellemeye çalıştığımız şeydir.</para>
/// </summary>
public interface IPinAttemptLimiter
{
    /// <summary>
    /// Bir tahmin hakkı tüketir. <c>false</c> → pencere dolu (ya da tablo kapasitesi aşıldı).
    /// </summary>
    bool TryConsume(string uuid);
}

public sealed class PinAttemptLimiter : IPinAttemptLimiter
{
    private sealed class Window
    {
        public int Count;
        public DateTime StartUtc;
    }

    private readonly ConcurrentDictionary<string, Window> _windows = new(StringComparer.Ordinal);
    private readonly Func<DateTime> _now;
    private readonly int _maxPerWindow;
    private readonly TimeSpan _windowLength;
    private readonly int _maxTrackedUuids;
    private readonly TimeSpan _sweepInterval = TimeSpan.FromMinutes(5);
    private long _lastSweepTicks;

    /// <param name="maxPerWindow">
    /// Relay'in kotasından (10/gün) bilinçli olarak GEVŞEK tutulur: normal işleyişte yalnız relay
    /// sayacı bağlayıcı olsun, bu yalnız relay atlandığında devreye girsin. 10 ile 20 arasındaki fark
    /// 10^6'lık uzay karşısında önemsizdir; önemli olan büyüklük mertebesi (saatler → yıllar).
    /// </param>
    public PinAttemptLimiter(
        int maxPerWindow = 20,
        TimeSpan? windowLength = null,
        int maxTrackedUuids = 100_000,
        Func<DateTime>? now = null)
    {
        _maxPerWindow = maxPerWindow;
        _windowLength = windowLength ?? TimeSpan.FromHours(24);
        _maxTrackedUuids = maxTrackedUuids;
        _now = now ?? (() => DateTime.UtcNow);
        _lastSweepTicks = _now().Ticks;
    }

    public bool TryConsume(string uuid)
    {
        if (string.IsNullOrEmpty(uuid)) return false;

        var now = _now();
        MaybeSweep(now);

        if (!_windows.TryGetValue(uuid, out var window))
        {
            // Kapasite kontrolü YALNIZCA yeni uuid eklerken. Yarış nedeniyle sınır biraz aşılabilir
            // (birkaç girdi) — kabul; amaç sınırsız büyümeyi engellemek, tam sayı tutmak değil.
            if (_windows.Count >= _maxTrackedUuids)
            {
                Sweep(now);
                if (_windows.Count >= _maxTrackedUuids)
                {
                    Console.WriteLine("[PinAttemptLimiter] Takip tablosu dolu — yeni uuid reddedildi (fail-closed).");
                    return false;
                }
            }
            window = _windows.GetOrAdd(uuid, _ => new Window { StartUtc = now });
        }

        lock (window)
        {
            if (now - window.StartUtc >= _windowLength)
            {
                window.StartUtc = now;
                window.Count = 0;
            }

            if (window.Count >= _maxPerWindow) return false;
            window.Count++;
            return true;
        }
    }

    /// <summary>Süpürmeyi en fazla <see cref="_sweepInterval"/>'de bir çalıştırır (amortize maliyet).</summary>
    private void MaybeSweep(DateTime now)
    {
        var last = Interlocked.Read(ref _lastSweepTicks);
        if (now.Ticks - last < _sweepInterval.Ticks) return;
        // Yalnız bir thread süpürsün; kaybeden thread'ler beklemez.
        if (Interlocked.CompareExchange(ref _lastSweepTicks, now.Ticks, last) != last) return;
        Sweep(now);
    }

    /// <summary>
    /// Süresi dolmuş pencereleri kaldırır. Süresi dolmuş bir pencereyi silmek, ilk erişimde
    /// sıfırlanacak olmasıyla EŞDEĞERDİR → sayaç kaybı yaratmaz.
    /// </summary>
    private void Sweep(DateTime now)
    {
        foreach (var kv in _windows)
        {
            bool expired;
            lock (kv.Value) { expired = now - kv.Value.StartUtc >= _windowLength; }
            if (expired) _windows.TryRemove(kv.Key, out _);
        }
    }
}
