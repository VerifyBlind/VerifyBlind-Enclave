using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using VerifyBlind.Enclave.Services;
using Xunit;
using Xunit.Abstractions;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Selfie ≈ DG2 ÜST SINIRI için ölçüm (güvenlik denetimi #2).
///
/// <para><b>Kapatılmak istenen saldırı:</b> kurcalanmış bir istemci, selfie alanına kurbanın
/// kendi çip fotoğrafını (DG2) koyar. Enclave selfie'yi DG2 ile karşılaştırdığı için benzerlik
/// ~1.0 çıkar ve kapı açılır. Saldırganın kurbanın HİÇBİR fotoğrafına ihtiyacı yoktur —
/// referans kartın içindedir. Anti-spoof ayrı bir alandan geldiği için onu da besleyebilir.</para>
///
/// <para><b>Savunma:</b> benzerliğe bir ÜST sınır koymak. Gerçek bir selfie, sıkıştırılmış çip
/// fotoğrafına karşı asla ~1.0 skorlamaz; cross-domain fark buna izin vermez. Ama sınırı körlemesine
/// koyamayız: meşru kullanıcının tavanının ÜSTÜNDE, enjeksiyonun tabanının ALTINDA olmalı.</para>
///
/// <para><b>Bu test o iki sayıyı ölçer</b> (eşik ÖNERMEZ, karar veriye bakılarak elle verilir):
///   (1) Özdeş görüntü → beklenen ~1.0. Enjeksiyonun tabanı.
///   (2) JPEG yeniden kodlanmış aynı görüntü → saldırgan DG2'yi aynen değil, yeniden sıkıştırarak
///       gönderebilir. Enjeksiyonun GERÇEKÇİ tabanı budur, (1) değil.
///   (3) LFW'de aynı kişinin FARKLI fotoğrafları → meşru kullanıcının tavanı.
/// Sınır (2) ile (3) arasına konmalı. Aralık yoksa bu savunma çalışmaz ve bunu bilmek gerekir.</para>
///
/// <para>Env-gated: <c>LFW_DIR</c> yoksa (1) ve (2) yine ölçülür; (3) atlanır.
/// Çalıştırma: <c>$env:LFW_DIR="C:/tmp/lfw_work/subset"; dotnet test --filter
/// FullyQualifiedName~SelfMatchCeilingTests</c></para>
/// </summary>
public class SelfMatchCeilingTests
{
    private readonly ITestOutputHelper _out;
    public SelfMatchCeilingTests(ITestOutputHelper output) => _out = output;

    private static readonly string[] Exts = { ".jpg", ".jpeg", ".png", ".bmp" };

    [Fact]
    public void MeasureSelfMatchCeilingAndGenuineCeiling()
    {
        var svc = new BiometricService();
        if (!svc.IsModelLoaded)
        {
            _out.WriteLine("[ATLANDI] w600k_r50.onnx yüklenmedi.");
            return;
        }

        var dir = Environment.GetEnvironmentVariable("LFW_DIR");
        var haveLfw = !string.IsNullOrEmpty(dir) && Directory.Exists(dir);
        if (!haveLfw)
            _out.WriteLine("[UYARI] LFW_DIR yok — genuine tavanı (3) ölçülemeyecek.");

        // Ölçüm için gerçek yüz görüntüleri gerekir; sentetik fixture decode bile edilemez.
        var samples = haveLfw
            ? Directory.GetDirectories(dir!).OrderBy(p => p)
                .SelectMany(d => Directory.GetFiles(d).Where(f => Exts.Contains(Path.GetExtension(f).ToLowerInvariant())))
                .Take(120).ToList()
            : new List<string>();

        if (samples.Count == 0)
        {
            _out.WriteLine("[ATLANDI] Ölçülecek gerçek yüz görüntüsü yok.");
            return;
        }

        // --- (1) ÖZDEŞ görüntü: aynı baytlar iki kez ---
        var identical = new List<float>();
        foreach (var f in samples.Take(40))
        {
            var bytes = File.ReadAllBytes(f);
            try { identical.Add(svc.VerifyFaceParallel(bytes, bytes)); } catch { /* yüz bulunamadı */ }
        }

        // --- (2) JPEG YENİDEN KODLANMIŞ aynı görüntü ---
        var recoded = new List<float>();
        foreach (var f in samples.Take(40))
        {
            var bytes = File.ReadAllBytes(f);
            foreach (var q in new[] { 90, 75, 60 })
            {
                try
                {
                    var re = Recode(bytes, q);
                    recoded.Add(svc.VerifyFaceParallel(bytes, re));
                }
                catch { /* atla */ }
            }
        }

        // --- (3) GENUINE: aynı kişi, FARKLI fotoğraf ---
        var genuine = new List<float>();
        if (haveLfw)
        {
            foreach (var personDir in Directory.GetDirectories(dir!).OrderBy(p => p))
            {
                var files = Directory.GetFiles(personDir)
                    .Where(f => Exts.Contains(Path.GetExtension(f).ToLowerInvariant()))
                    .OrderBy(p => p).ToList();
                if (files.Count < 2) continue;
                for (int i = 0; i < files.Count - 1 && genuine.Count < 400; i++)
                {
                    try { genuine.Add(svc.VerifyFaceParallel(File.ReadAllBytes(files[i]), File.ReadAllBytes(files[i + 1]))); }
                    catch { /* atla */ }
                }
                if (genuine.Count >= 400) break;
            }
        }

        Report("(1) ÖZDEŞ  (enjeksiyon, ideal)", identical);
        Report("(2) YENİDEN KODLANMIŞ (enjeksiyon, gerçekçi)", recoded);
        Report("(3) GENUINE aynı kişi farklı foto (meşru tavan)", genuine);

        if (recoded.Count > 0 && genuine.Count > 0)
        {
            var attackFloor = recoded.Min();
            var genuineCeil = genuine.Max();
            _out.WriteLine("");
            _out.WriteLine($"ENJEKSİYON TABANI (2 min) = {attackFloor:F4}");
            _out.WriteLine($"MEŞRU TAVAN       (3 max) = {genuineCeil:F4}");
            _out.WriteLine(attackFloor > genuineCeil
                ? $"→ AYRILABİLİR. Üst sınır bu ikisinin ARASINA konmalı (ör. {(attackFloor + genuineCeil) / 2:F3})."
                : "→ AYRILAMAZ: enjeksiyon tabanı meşru tavanın ALTINDA. Üst sınır meşru kullanıcıyı keser; bu savunma TEK BAŞINA çalışmaz.");
        }

        // Bu test bir ÖLÇÜM aracıdır; eşik doğrulamaz. Assert YOK ki sayılar her koşuda okunabilsin.
        Assert.True(identical.Count > 0, "Hiç ölçüm yapılamadı — model/görüntü sorunu.");
    }

    private void Report(string label, List<float> xs)
    {
        if (xs.Count == 0) { _out.WriteLine($"{label}: ölçüm yok"); return; }
        var s = xs.OrderBy(x => x).ToList();
        _out.WriteLine($"{label}: n={s.Count} min={s.First():F4} p05={Pct(s, 0.05):F4} " +
                       $"medyan={Pct(s, 0.50):F4} p95={Pct(s, 0.95):F4} max={s.Last():F4}");
    }

    private static float Pct(List<float> sorted, double p)
    {
        if (sorted.Count == 0) return 0f;
        var idx = (int)Math.Round(p * (sorted.Count - 1));
        return sorted[Math.Clamp(idx, 0, sorted.Count - 1)];
    }

    /// <summary>JPEG olarak yeniden kodlar — saldırganın DG2'yi aynen değil, işleyerek göndermesi.</summary>
    private static byte[] Recode(byte[] input, int quality)
    {
        using var img = SixLabors.ImageSharp.Image.Load(input);
        using var ms = new MemoryStream();
        img.Save(ms, new SixLabors.ImageSharp.Formats.Jpeg.JpegEncoder { Quality = quality });
        return ms.ToArray();
    }
}
