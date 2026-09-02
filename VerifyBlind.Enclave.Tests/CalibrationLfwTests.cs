using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using VerifyBlind.Enclave.Services;
using Xunit;
using Xunit.Abstractions;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// GERÇEK C# pipeline'ı LFW'de uçtan uca çalıştıran eşik kalibrasyon/doğrulama testi.
/// Env-gated: LFW_DIR yoksa atlanır (CI'da no-op). Lokal çalıştırma:
///   $env:LFW_DIR="C:/tmp/lfw_work/subset"; dotnet test --filter FullyQualifiedName~CalibrationLfwTests
/// Amaç: hizalı (YuNet+Umeyama+warp) C# boru hattının numpy referansıyla (EER ~%1.56,
/// FAR≤%0.1'de FRR ~%1.70) AYNI sonucu verdiğini kanıtlamak + önerilen eşiği üretmek.
/// Numpy referans: tools/biometric/yunet_frr_ref.py.
/// </summary>
public class CalibrationLfwTests
{
    private readonly ITestOutputHelper _out;
    public CalibrationLfwTests(ITestOutputHelper output) => _out = output;

    private static readonly string[] Exts = { ".jpg", ".jpeg", ".png", ".bmp" };

    [Fact]
    public void LfwAlignedFrr_ReportsThresholdAndBeatsCenterCrop()
    {
        var dir = Environment.GetEnvironmentVariable("LFW_DIR");
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
        {
            _out.WriteLine("[ATLANDI] LFW_DIR ayarlı değil — yerel kalibrasyon testi atlandı.");
            return;
        }

        var svc = new BiometricService();
        if (!svc.IsModelLoaded)
        {
            _out.WriteLine("[ATLANDI] w600k_r50.onnx yüklenmedi.");
            return;
        }

        // 1) Her görüntüyü BİR kez embed et (L2-normalize), kişi-bazlı grupla.
        var identities = new Dictionary<string, List<float[]>>();
        int total = 0, skipped = 0;
        foreach (var personDir in Directory.GetDirectories(dir).OrderBy(p => p))
        {
            var embs = new List<float[]>();
            foreach (var f in Directory.GetFiles(personDir).OrderBy(p => p))
            {
                if (!Exts.Contains(Path.GetExtension(f).ToLowerInvariant())) continue;
                try
                {
                    var emb = Normalize(svc.GetEmbedding(File.ReadAllBytes(f)));
                    if (emb != null) { embs.Add(emb); total++; }
                    else skipped++;
                }
                catch { skipped++; }
            }
            if (embs.Count >= 2)
                identities[Path.GetFileName(personDir)] = embs;
        }
        _out.WriteLine($"[+] {identities.Count} kişi, {total} foto (atlanan: {skipped})");
        Assert.True(identities.Count >= 4, "Held-out split için en az 4 kişi gerekli.");

        // 2) SIZINTISIZ kişi-bazlı 70/30 train/test split (calibrate_threshold.py ile aynı yöntem).
        var rng = new Random(42);
        var ids = identities.Keys.OrderBy(k => k).OrderBy(_ => rng.Next()).ToList();
        int cut = Math.Max(1, (int)(ids.Count * 0.7));
        var trainIds = new HashSet<string>(ids.Take(cut));
        var train = identities.Where(kv => trainIds.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value);
        var test = identities.Where(kv => !trainIds.Contains(kv.Key)).ToDictionary(kv => kv.Key, kv => kv.Value);

        var (gTr, imTr) = MakePairs(train, rng);
        var (gTe, imTe) = MakePairs(test, rng);
        _out.WriteLine($"[+] train: {gTr.Length} genuine / {imTr.Length} impostor  |  test: {gTe.Length} genuine / {imTe.Length} impostor");

        // 3) TRAIN'de EER + hedef-FAR eşikleri; HELD-OUT TEST'te o eşiklerin gerçek FAR/FRR'si.
        double eerT = 0, eerGap = double.MaxValue, eerVal = 1;
        for (double t = 0; t <= 1.0001; t += 0.005)
        {
            double far = Frac(imTr, x => x >= t), frr = Frac(gTr, x => x < t);
            if (Math.Abs(far - frr) < eerGap) { eerGap = Math.Abs(far - frr); eerT = t; eerVal = (far + frr) / 2; }
        }
        _out.WriteLine($"\n[TRAIN] EER ~ %{eerVal * 100:0.00} @ eşik {eerT:0.000}");
        _out.WriteLine("Hedef-FAR | train eşik | HELD-OUT TEST: gerçek FAR / FRR(red)");
        foreach (var tf in new[] { 0.01, 0.001, 0.0001 })
        {
            double chosenT = -1;
            for (double t = 0; t <= 1.0001; t += 0.005)
                if (Frac(imTr, x => x >= t) <= tf) { chosenT = t; break; }
            if (chosenT < 0) continue;
            double farTe = Frac(imTe, x => x >= chosenT), frrTe = Frac(gTe, x => x < chosenT);
            _out.WriteLine($"  FAR≤%{tf * 100,5:0.00} | {chosenT,6:0.000}    | TEST FAR %{farTe * 100:0.000}  FRR %{frrTe * 100:0.00}");
        }

        // 4) Aday eşiklerin TEST FRR'si (karar için ham tablo).
        _out.WriteLine("\nAday eşik | TEST FAR / FRR (cross-domain'de FRR daha yüksek olur — muhafazakâr seç):");
        foreach (var t in new[] { 0.15, 0.18, 0.20, 0.22, 0.25, 0.30, 0.40 })
            _out.WriteLine($"  {t:0.00} | TEST FAR %{Frac(imTe, x => x >= t) * 100:0.000}  FRR %{Frac(gTe, x => x < t) * 100:0.00}");
        _out.WriteLine("(KIYAS — center-crop: EER ~%7, FAR≤%0.1'de FRR ~%46 ; hizalı THRESHOLD=0.20 — EnclaveService.cs)");

        Assert.True(eerVal < 0.04, $"TRAIN EER %{eerVal * 100:0.00} beklenenden yüksek — hizalama bozuk olabilir.");
    }

    /// <summary>Genuine: aynı kişi tüm çiftler. Impostor: farklı kişi, örneklenmiş (≤100k).</summary>
    private static (double[] genuine, double[] impostor) MakePairs(Dictionary<string, List<float[]>> ids, Random rng)
    {
        var genuine = new List<double>();
        foreach (var embs in ids.Values)
            for (int i = 0; i < embs.Count; i++)
                for (int j = i + 1; j < embs.Count; j++)
                    genuine.Add(Dot(embs[i], embs[j]));

        var flat = ids.SelectMany(kv => kv.Value.Select(e => (kv.Key, e))).ToList();
        var impostor = new List<double>();
        int tries = 0, max = Math.Min(100_000, Math.Max(2000, flat.Count * flat.Count));
        while (impostor.Count < max && tries < max * 20 && flat.Count > 1)
        {
            tries++;
            var a = flat[rng.Next(flat.Count)];
            var b = flat[rng.Next(flat.Count)];
            if (a.Key == b.Key) continue;
            impostor.Add(Dot(a.e, b.e));
        }
        return (genuine.OrderBy(x => x).ToArray(), impostor.OrderBy(x => x).ToArray());
    }

    private static float[]? Normalize(float[]? e)
    {
        if (e == null || e.Length == 0) return null;
        double n = Math.Sqrt(e.Sum(v => (double)v * v));
        if (n == 0) return null;
        return e.Select(v => (float)(v / n)).ToArray();
    }

    private static double Dot(float[] a, float[] b)
    {
        double s = 0;
        for (int i = 0; i < a.Length; i++) s += (double)a[i] * b[i];
        return s;
    }

    private static double Frac(double[] sorted, Func<double, bool> pred)
    {
        int c = 0;
        foreach (var v in sorted) if (pred(v)) c++;
        return (double)c / sorted.Length;
    }
}
