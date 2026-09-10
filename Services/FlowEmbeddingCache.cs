using System.Collections.Concurrent;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Canlı benzerlik akışı için DG2 gömme vektörü önbelleği — YALNIZ RAM, TTL'li, tavanlı.
///
/// <para>Neden gerekli: DG2 telefonda NFC'den okunur ve enclave'e bugün ancak register anında,
/// şifreli yükte gider. Canlılık sürerken enclave'in kıyaslayacak referansı yoktur. Akış başında
/// DG2 bir kez gönderilir, enclave ArcFace gömme vektörünü hesaplayıp burada tutar (512 float ≈
/// 2 KB); sonraki her karede yalnız selfie + kırpma gider.</para>
///
/// <para>⚠️ FOTOĞRAFIN KENDİSİ SAKLANMAZ — yalnız gömme vektörü. Enclave'in diski yoktur; bu
/// RAM'de yaşar ve akış bitince ya da TTL dolunca silinir.</para>
///
/// <para>⚠️ FINAL REGISTER BU ÖNBELLEĞE ASLA BAKMAZ (K4). Register DG2'yi bugünkü gibi şifreli
/// yükten okur ve her şeyi baştan hesaplar; "önceden onaylanmış" diye bir kavram yoktur. Bu sınıf
/// tamamen kaldırılsa register aynen çalışır.</para>
/// </summary>
public class FlowEmbeddingCache
{
    /// <summary>
    /// Girdi ömrü. Nonce penceresiyle (15 dk) hizalı: streaming yalnız o pencerede anlamlıdır,
    /// çünkü akış zaten nonce süresi dolunca register edemez.
    /// </summary>
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Eşzamanlı akış tavanı. Girdi başına ~2 KB (512 float) + anahtar → 5.000 girdi ≈ 10 MB.
    /// Tavan bir bellek freni: uç kimlik doğrulaması istemez, dolayısıyla rastgele flow_id ile
    /// sınırsız girdi açılabilirdi. Doluyken en eski girdiler atılır.
    /// </summary>
    public const int MaxEntries = 5_000;

    private sealed record Entry(float[] Embedding, DateTimeOffset ExpiresAt);

    private readonly ConcurrentDictionary<string, Entry> _entries = new();

    /// <summary>
    /// Saat kaynağı — testlerde TTL davranışını gerçekten DOĞRULAYABİLMEK için enjekte edilir.
    /// Üretimde her zaman <see cref="DateTimeOffset.UtcNow"/>.
    ///
    /// Neden gerekli: "gömme vektörü TTL sonunda RAM'den siliniyor" bu işin kabul ölçütlerinden
    /// biri. Saat sabitlenmeden bu ancak 15 dakika bekleyen bir testle sınanabilirdi, yani
    /// pratikte hiç sınanmazdı.
    /// </summary>
    private readonly Func<DateTimeOffset> _now;

    public FlowEmbeddingCache() : this(() => DateTimeOffset.UtcNow) { }

    internal FlowEmbeddingCache(Func<DateTimeOffset> now) => _now = now;

    /// <summary>
    /// Akışın gömme vektörünü saklar. Aynı flow_id tekrar hazırlanırsa üzerine yazılır
    /// (kullanıcı NFC'yi yeniden okutabilir).
    /// </summary>
    public void Store(string flowId, float[] embedding)
    {
        Prune();

        // Tavan hâlâ doluysa yeni girdi kabul edilmez: kapasiteyi taze isteklere açık tutmak
        // için en eskiyi atmak, meşru bir akışın referansını ortasında düşürmek olurdu.
        // Bunun yerine streaming o akış için sessizce devre dışı kalır — cihaz kendi 0.65
        // kapısıyla çalışmaya devam eder ve kullanıcı hiçbir şey kaybetmez.
        if (_entries.Count >= MaxEntries && !_entries.ContainsKey(flowId))
        {
            Console.WriteLine($"[FlowEmbeddingCache] Tavan dolu ({MaxEntries}) — akış eklenmedi.");
            return;
        }

        _entries[flowId] = new Entry(embedding, _now().Add(Ttl));
    }

    /// <summary>Akışın gömme vektörünü döner; yoksa ya da süresi dolmuşsa null.</summary>
    public float[]? Get(string flowId)
    {
        if (!_entries.TryGetValue(flowId, out var entry)) return null;

        if (entry.ExpiresAt <= _now())
        {
            _entries.TryRemove(flowId, out _);
            return null;
        }

        return entry.Embedding;
    }

    /// <summary>Akış bitti — girdiyi hemen sil (TTL'i bekleme).</summary>
    public void Remove(string flowId) => _entries.TryRemove(flowId, out _);

    /// <summary>Teşhis/test için: şu anda tutulan girdi sayısı.</summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Süresi dolmuş girdileri temizler. Ayrı bir zamanlayıcı YOK: temizlik yazma yolunda
    /// yapılır — enclave'de arka plan işi ne kadar azsa o kadar iyi ve girdi sayısı zaten
    /// yalnız yazmayla artar.
    /// </summary>
    private void Prune()
    {
        var now = _now();
        foreach (var kv in _entries)
            if (kv.Value.ExpiresAt <= now)
                _entries.TryRemove(kv.Key, out _);
    }
}
