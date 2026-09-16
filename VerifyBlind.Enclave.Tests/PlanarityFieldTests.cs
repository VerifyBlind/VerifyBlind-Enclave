using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.FaceAlignment;
using Xunit;
using Xunit.Abstractions;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// SAHA ÖLÇÜMÜ — düzlem-dışılık sınamasının GERÇEK fotoğraflar üzerinde çalışıp çalışmadığını
/// kayıt akışına hiç dokunmadan ölçer.
///
/// <para><b>Neden bu test var:</b> ilk saha turunda (2026-09-16) monitör denemeleri geçersiz
/// çıktı — kullanıcı telefonu monitöre değil kendi yüzüne yaklaştırmıştı, yani "kamera düz bir
/// yüzeye yaklaşıyor" durumu HİÇ ölçülmedi. Kayıt akışı içinde doğru test etmek tek başına
/// neredeyse imkânsız (telefon monitörün dibinde sabit durmak zorunda). Oysa ölçülmek istenen
/// şey saf geometri: dört klasör fotoğraf yeter.</para>
///
/// <para><b>Beklenti:</b> gerçek yüzde yaklaşınca burun artığı ARTAR (ilk sahada 5/5 arttı);
/// düz bir yüzeyde (TV/monitör/baskı) DEĞİŞMEMELİ, çünkü düzlemsel bir nesnenin her katı
/// hareketi bir homografidir ve homografi artığı soğurur.</para>
///
/// <para><b>Çalıştırma</b> (PowerShell):</para>
/// <code>
/// $env:PLANARITY_DIR="C:/tmp/zoomtest"
/// dotnet test --filter FullyQualifiedName~PlanarityFieldTests -l "console;verbosity=detailed"
/// </code>
///
/// <para><b>Klasör düzeni</b> — dördü de <c>PLANARITY_DIR</c> altında:</para>
/// <code>
/// face_far/    gerçek yüz, kol mesafesi     (8 foto)
/// face_near/   gerçek yüz, yakın            (8 foto)
/// screen_far/  TV'deki yüz, uzaktan         (8 foto)
/// screen_near/ TV'deki yüz, yakından        (8 foto)
/// </code>
///
/// <para>⚠️ Bu bir KARAR testi değil, bir ÖLÇÜM aracıdır: eşiği yoktur ve hiçbir şeyi
/// başarısız saymaz. Sayıları basar, hükmü insan verir. Klasör yoksa sessizce atlanır.</para>
/// </summary>
public class PlanarityFieldTests
{
    private readonly ITestOutputHelper _out;
    public PlanarityFieldTests(ITestOutputHelper output) => _out = output;

    private static readonly string[] Exts = { ".jpg", ".jpeg", ".png", ".bmp", ".heic", ".webp" };

    [Fact]
    public void MeasureFolders_ReportsSignalForRealFaceAndFlatScreen()
    {
        var root = Environment.GetEnvironmentVariable("PLANARITY_DIR");
        if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
        {
            _out.WriteLine("[ATLANDI] PLANARITY_DIR ayarlı değil — saha ölçümü atlandı.");
            return;
        }

        var svc = new BiometricService();

        var face = Measure(svc, root, "face_far", "face_near");
        var screen = Measure(svc, root, "screen_far", "screen_near");

        _out.WriteLine("");
        _out.WriteLine("========================= SONUÇ =========================");

        if (face != null)
            _out.WriteLine($"GERÇEK YÜZ   sinyal = {face.Value.delta:F5}   " +
                           $"(uzak {face.Value.far:F5} → yakın {face.Value.near:F5}, " +
                           $"yaklaşma {face.Value.iedRatio:F2}×)");
        if (screen != null)
            _out.WriteLine($"EKRAN        sinyal = {screen.Value.delta:F5}   " +
                           $"(uzak {screen.Value.far:F5} → yakın {screen.Value.near:F5}, " +
                           $"yaklaşma {screen.Value.iedRatio:F2}×)");

        if (face != null && screen != null)
        {
            _out.WriteLine("");
            // Asıl soru tek cümle: düz yüzey, gerçek yüzden BELİRGİN biçimde daha az sinyal
            // üretiyor mu? Üretmiyorsa mekanizma bu biçimiyle kullanılamaz.
            _out.WriteLine(screen.Value.delta < face.Value.delta
                ? $"→ Ekran daha AZ sinyal üretti (oran {face.Value.delta / Math.Max(screen.Value.delta, 1e-6):F1}×). " +
                  "Beklenen yön BU."
                : "→ Ekran gerçek yüz kadar ya da daha ÇOK sinyal üretti. " +
                  "Mekanizma bu biçimiyle ayırt etmiyor.");

            _out.WriteLine("");
            _out.WriteLine("⚠️ Yaklaşma oranları birbirine yakın DEĞİLSE karşılaştırma adil değildir " +
                           "— sinyal mesafe değişiminden doğar.");
        }

        _out.WriteLine("=========================================================");
    }

    private (double far, double near, double delta, double iedRatio)? Measure(
        BiometricService svc, string root, string farName, string nearName)
    {
        var far = LoadWindow(svc, Path.Combine(root, farName), farName);
        var near = LoadWindow(svc, Path.Combine(root, nearName), nearName);
        if (far.Count == 0 || near.Count == 0)
        {
            _out.WriteLine($"[ATLANDI] {farName}/{nearName} — ölçülebilen kare yok.");
            return null;
        }

        var farOffset = PlanarityProbe.MedianOffset(far);
        var nearOffset = PlanarityProbe.MedianOffset(near);
        double? delta = PlanarityProbe.Delta(far, near);
        double? farIed = PlanarityProbe.MedianInterocular(far);
        double? nearIed = PlanarityProbe.MedianInterocular(near);

        if (farOffset == null || nearOffset == null || delta == null) return null;

        return (farOffset.Value.Magnitude, nearOffset.Value.Magnitude, delta.Value,
                farIed is > 0 && nearIed is > 0 ? nearIed.Value / farIed.Value : 0);
    }

    /// <summary>
    /// Bir klasörün fotoğraflarından 5-nokta kümesi çıkarır ve her karenin ölçüsünü basar.
    /// Kare kare basmak şart: tek bozuk fotoğrafın medyanı nasıl etkilediğini ancak böyle görürüz.
    /// </summary>
    private List<float[]> LoadWindow(BiometricService svc, string dir, string label)
    {
        var result = new List<float[]>();
        if (!Directory.Exists(dir))
        {
            _out.WriteLine($"[YOK] {label}: klasör bulunamadı ({dir})");
            return result;
        }

        var files = Directory.EnumerateFiles(dir)
            .Where(f => Exts.Contains(Path.GetExtension(f).ToLowerInvariant()))
            .OrderBy(f => f)
            .ToList();

        _out.WriteLine($"--- {label} ({files.Count} dosya) ---");

        foreach (var file in files)
        {
            float[]? lm;
            try
            {
                lm = svc.DetectLandmarks(File.ReadAllBytes(file));
            }
            catch (Exception ex)
            {
                _out.WriteLine($"  {Path.GetFileName(file),-28} HATA: {ex.GetType().Name}");
                continue;
            }

            if (lm == null)
            {
                _out.WriteLine($"  {Path.GetFileName(file),-28} yüz bulunamadı");
                continue;
            }

            var offset = PlanarityProbe.NoseResidualVector(lm);
            double? ied = PlanarityProbe.Interocular(lm);
            _out.WriteLine($"  {Path.GetFileName(file),-28} artık={offset?.Magnitude:F5}  " +
                           $"(x={offset?.X:+0.00000;-0.00000}, y={offset?.Y:+0.00000;-0.00000})  " +
                           $"gözArası={ied:F1}px");

            result.Add(lm);
        }

        return result;
    }
}
