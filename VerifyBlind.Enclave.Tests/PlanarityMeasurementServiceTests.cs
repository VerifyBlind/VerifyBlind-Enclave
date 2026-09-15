using System;
using System.Collections.Generic;
using System.Linq;
using Moq;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Yakınlaştırma ölçümünün SÖZLEŞMESİ: bir gözlem yoludur, karar yolu değil.
///
/// <para>Bu testlerin ortak teması tek cümle: <b>ölçüm hiçbir koşulda kaydı düşürmez.</b>
/// Kanıt yoksa, kareler bozuksa, yüz bulunamazsa, dedektör istisna atarsa — hepsinde sonuç
/// bir DURUM etiketidir, bir istisna değil. Kapı ileride açılacaksa bile bu ayrım korunmalı:
/// "ölçemedik" ile "sahte" aynı şey değildir.</para>
/// </summary>
public class PlanarityMeasurementServiceTests
{
    // --- Sentetik nokta üretimi (PlanarityProbeTests ile aynı kamera/yüz modeli) ---
    private const double FocalPx = 1400, Cx = 540, Cy = 960, NoseMm = 20.0;

    private static float[] RealFace(double distanceMm)
    {
        double[,] pts =
        {
            { -31.50,   0.17, 0.0     },
            {  31.50,  -0.17, 0.0     },
            {   0.20,  36.00, -NoseMm },
            { -25.70,  72.90, 0.0     },
            {  26.50,  72.60, 0.0     },
        };

        var lm = new float[10];
        for (int i = 0; i < 5; i++)
        {
            double z = distanceMm + pts[i, 2];
            lm[2 * i] = (float)(FocalPx * pts[i, 0] / z + Cx);
            lm[2 * i + 1] = (float)(FocalPx * pts[i, 1] / z + Cy);
        }
        return lm;
    }

    private static ZoomProof Proof(int farCount, int nearCount)
    {
        string frame = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        return new ZoomProof
        {
            FarFrames = Enumerable.Repeat(frame, farCount).ToList(),
            NearFrames = Enumerable.Repeat(frame, nearCount).ToList(),
        };
    }

    /// <summary>Uzak kareler için 600 mm, yakın kareler için 250 mm nokta döndüren sahte dedektör.</summary>
    private static Mock<IBiometricService> Detector(int farCount)
    {
        var mock = new Mock<IBiometricService>();
        int call = 0;
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>()))
            .Returns(() => RealFace(call++ < farCount ? 600 : 250));
        return mock;
    }

    // =========================================================================================

    /// <summary>Kanıt yoksa ölçüm yok — ve bu bir hata DEĞİL.</summary>
    [Fact]
    public void NoProof_ReturnsNoProofStatus_WithoutTouchingDetector()
    {
        var detector = new Mock<IBiometricService>(MockBehavior.Strict);
        var svc = new PlanarityMeasurementService(detector.Object);

        Assert.Equal("no_proof", svc.Measure(null).Status);
        Assert.Equal("no_proof", svc.Measure(new ZoomProof()).Status);

        detector.Verify(b => b.DetectLandmarks(It.IsAny<byte[]>()), Times.Never);
    }

    /// <summary>Tam kanıt → ölçüldü, sinyal hesaplandı, yaklaşma oranı raporlandı.</summary>
    [Fact]
    public void FullProof_MeasuresDeltaAndIedRatio()
    {
        var svc = new PlanarityMeasurementService(Detector(farCount: 6).Object);
        PlanarityOutcome outcome = svc.Measure(Proof(6, 6));

        Assert.Equal("measured", outcome.Status);
        Assert.Equal(6, outcome.FarMeasured);
        Assert.Equal(6, outcome.NearMeasured);
        Assert.NotNull(outcome.Delta);
        Assert.True(outcome.Delta > 0.01, $"Gerçek yüz sinyali beklenirdi, delta={outcome.Delta}");

        // Yaklaşma gerçekten oldu: 600 → 250 mm ≈ 2,4×
        Assert.NotNull(outcome.IedRatio);
        Assert.True(outcome.IedRatio > 2.0, $"IED oranı={outcome.IedRatio}");
    }

    /// <summary>
    /// Az kare → sayı yine hesaplanır ama "ölçüldü" DENMEZ. Eşik çalışması güvenilmez
    /// pencereleri kendi dağılımına karıştırmamalı.
    /// </summary>
    [Fact]
    public void TooFewFrames_ComputesValue_ButFlagsStatus()
    {
        var svc = new PlanarityMeasurementService(Detector(farCount: 2).Object);
        PlanarityOutcome outcome = svc.Measure(Proof(2, 2));

        Assert.Equal("not_enough_frames", outcome.Status);
        Assert.NotNull(outcome.Delta);   // veri kaybedilmez, yalnız etiketlenir
    }

    /// <summary>Hiç yüz bulunamazsa hangi pencerenin boş olduğu ayırt edilir — teşhis için.</summary>
    [Fact]
    public void NoFaceDetected_ReportsWhichWindowFailed()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>())).Returns((float[]?)null);

        var outcome = new PlanarityMeasurementService(mock.Object).Measure(Proof(5, 5));

        Assert.Equal("no_face_far", outcome.Status);
        Assert.Equal(0, outcome.FarMeasured);
        Assert.Null(outcome.Delta);
    }

    /// <summary>
    /// Kullanıcı yaklaştı (istemci öyle diyor) ama kamera yakın pencerede yüz göremedi —
    /// bu bir KAMERA sorunudur ve öyle etiketlenmeli.
    /// </summary>
    [Fact]
    public void NoFaceInNearWindowOnly_IsDistinguished()
    {
        var mock = new Mock<IBiometricService>();
        int call = 0;
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>()))
            .Returns(() => call++ < 5 ? RealFace(600) : null);

        var proof = Proof(5, 5);
        proof.ReachedTarget = true;

        var outcome = new PlanarityMeasurementService(mock.Object).Measure(proof);

        Assert.Equal("no_face_near", outcome.Status);
        Assert.Equal(5, outcome.FarMeasured);
        Assert.Equal(0, outcome.NearMeasured);
    }

    /// <summary>
    /// 🔴 Kullanıcı hiç yaklaşmadı → istemci yakın pencereyi BİLEREK boş gönderir.
    ///
    /// <para>Kamera arızasından AYRI etiketlenir. Bu satırların oranı, adımın acemi kullanıcıda
    /// çalışıp çalışmadığının tek ölçüsüdür: yüksekse sorun eşikte değil YÖNERGEDEDİR. İkisi
    /// tek etikette toplansaydı bu ayrım hiç görünmezdi.</para>
    /// </summary>
    [Fact]
    public void UserNeverApproached_IsLabelledSeparatelyFromCameraFailure()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>())).Returns(RealFace(600));

        var proof = new ZoomProof
        {
            FarFrames = Proof(6, 0).FarFrames,
            NearFrames = new List<string>(),   // istemci yarı yolda kare TOPLAMAZ
            ReachedTarget = false,
        };

        var outcome = new PlanarityMeasurementService(mock.Object).Measure(proof);

        Assert.Equal("not_approached", outcome.Status);
        Assert.Equal(6, outcome.FarMeasured);
        Assert.Equal(0, outcome.NearMeasured);
        // Yarım yaklaşmadan sayı ÜRETİLMEZ — üretilseydi dağılımı sahte veriyle doldururdu.
        Assert.Null(outcome.Delta);
    }

    /// <summary>Bozuk base64 kareyi düşürür, ölçümü durdurmaz.</summary>
    [Fact]
    public void CorruptFrame_IsSkipped_NotFatal()
    {
        var proof = Proof(5, 5);
        proof.FarFrames[2] = "bu-base64-değil!!!";
        proof.NearFrames[0] = "";

        var outcome = new PlanarityMeasurementService(Detector(farCount: 4).Object).Measure(proof);

        Assert.Equal("measured", outcome.Status);
        Assert.Equal(4, outcome.FarMeasured);
        Assert.Equal(4, outcome.NearMeasured);
    }

    /// <summary>Şişirilmiş kare işlenmez — register ucuz bir CPU tüketim yüzeyi olmamalı.</summary>
    [Fact]
    public void OversizedFrame_IsSkipped()
    {
        var proof = Proof(4, 4);
        proof.FarFrames[0] = Convert.ToBase64String(new byte[300_000]);

        var detector = Detector(farCount: 3);
        var outcome = new PlanarityMeasurementService(detector.Object).Measure(proof);

        Assert.Equal(3, outcome.FarMeasured);
        detector.Verify(b => b.DetectLandmarks(It.Is<byte[]>(a => a.Length > 200_000)), Times.Never);
    }

    /// <summary>
    /// Pencere başına kare tavanı uygulanır: aday listesindeki "tavan iki" ile aynı gerekçe —
    /// uç, kaç çıkarım koşturacağımıza karar veremez.
    /// </summary>
    [Fact]
    public void FrameCount_IsCappedPerWindow()
    {
        var detector = Detector(farCount: PlanarityMeasurementService.MaxFramesPerWindow);
        var svc = new PlanarityMeasurementService(detector.Object);

        svc.Measure(Proof(50, 50));

        detector.Verify(b => b.DetectLandmarks(It.IsAny<byte[]>()),
            Times.Exactly(PlanarityMeasurementService.MaxFramesPerWindow * 2));
    }

    /// <summary>
    /// 🔴 Dedektör patlasa bile ölçüm istisna FIRLATMAZ. Bu, "ölçüm kaydı düşürmez"
    /// sözleşmesinin en sert hâli.
    /// </summary>
    [Fact]
    public void DetectorThrowing_DoesNotPropagate()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>()))
            .Throws(new InvalidOperationException("model yok"));

        var outcome = new PlanarityMeasurementService(mock.Object).Measure(Proof(5, 5));

        Assert.Equal("no_face_far", outcome.Status);
        Assert.Null(outcome.Delta);
    }

    /// <summary>
    /// Düz yüzey (monitör) sinyali ~0 üretmeli — servis katmanında da doğrulanır,
    /// yalnız saf matematikte değil.
    /// </summary>
    [Fact]
    public void FlatSurface_ProducesNearZeroSignal_ThroughService()
    {
        // Ekran: aynı düzlemsel nokta kümesi, yalnız ölçeklenmiş (kamera yaklaştı).
        float[] far = RealFace(600);
        var near = new float[10];
        for (int i = 0; i < 10; i++)
        {
            double centre = i % 2 == 0 ? Cx : Cy;
            near[i] = (float)(centre + (far[i] - centre) * 2.4);   // düz büyütme
        }

        var mock = new Mock<IBiometricService>();
        int call = 0;
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>()))
            .Returns(() => call++ < 5 ? far : near);

        var outcome = new PlanarityMeasurementService(mock.Object).Measure(Proof(5, 5));

        Assert.Equal("measured", outcome.Status);
        Assert.NotNull(outcome.Delta);
        Assert.True(outcome.Delta < 0.001,
            $"Düz yüzey sinyal üretmemeli, delta={outcome.Delta}");
    }
}
