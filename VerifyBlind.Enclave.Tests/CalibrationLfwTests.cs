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
        Assert.True(identities.Count >= 2, "En az 2 kişi gerekli.");

        // 2) Genuine (aynı kişi tüm çiftler) + impostor (farklı kişi, örneklenmiş) kosinüsleri.
        var genuine = new List<double>();
        foreach (var embs in identities.Values)
            for (int i = 0; i < embs.Count; i++)
                for (int j = i + 1; j < embs.Count; j++)
                    genuine.Add(Dot(embs[i], embs[j]));

        var flat = identities.SelectMany(kv => kv.Value.Select(e => (kv.Key, e))).ToList();
        var rng = new Random(42);
        var impostor = new List<double>();
        int tries = 0;
        while (impostor.Count < 200_000 && tries < 4_000_000)
        {
            tries++;
            var a = flat[rng.Next(flat.Count)];
            var b = flat[rng.Next(flat.Count)];
            if (a.Key == b.Key) continue;
            impostor.Add(Dot(a.e, b.e));
        }
        _out.WriteLine($"[+] {genuine.Count} genuine / {impostor.Count} impostor çift");

        // 3) Eşik taraması: EER + hedef-FAR noktaları.
        var g = genuine.OrderBy(x => x).ToArray();
        var im = impostor.OrderBy(x => x).ToArray();
        double bestT = 0, bestGap = double.MaxValue, eerVal = 1;
        for (double t = 0; t <= 1.0001; t += 0.005)
        {
            double far = Frac(im, x => x >= t);
            double frr = Frac(g, x => x < t);
            if (Math.Abs(far - frr) < bestGap) { bestGap = Math.Abs(far - frr); bestT = t; eerVal = (far + frr) / 2; }
        }
        _out.WriteLine($"\n[C#-HIZALI] EER ~ %{eerVal * 100:0.00}  @ eşik {bestT:0.000}");
        _out.WriteLine("Hedef-FAR tablosu (held-out değil, tüm LFW — referansla kıyas için):");
        foreach (var tf in new[] { 0.01, 0.001, 0.0001 })
        {
            double chosenT = -1, realFar = 0, frrAt = 0;
            for (double t = 0; t <= 1.0001; t += 0.005)
            {
                double far = Frac(im, x => x >= t);
                if (far <= tf) { chosenT = t; realFar = far; frrAt = Frac(g, x => x < t); break; }
            }
            if (chosenT >= 0)
                _out.WriteLine($"  FAR≤%{tf * 100:0.00}: eşik {chosenT:0.000}  gerçek FAR %{realFar * 100:0.000}  FRR %{frrAt * 100:0.00}");
        }
        _out.WriteLine("(KIYAS — numpy referans: EER ~%1.56 / FAR≤%0.1'de FRR ~%1.70 ; center-crop: EER ~%7, FRR ~%46)");

        // Sanity: hizalı boru hattı center-crop'tan (EER ~%7) ÇOK daha iyi olmalı.
        Assert.True(eerVal < 0.04, $"EER %{eerVal * 100:0.00} beklenenden yüksek — hizalama bozuk olabilir.");
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
