using System;
using System.Collections.Generic;
using System.Linq;
using Moq;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Parallaks ölçümünün SÖZLEŞMESİ: bir gözlem yoludur, karar yolu değil.
///
/// <para>Bu testlerin ortak teması tek cümle: <b>ölçüm hiçbir koşulda kaydı düşürmez.</b>
/// Kanıt yoksa, kareler bozuksa, yüz bulunamazsa, dedektör istisna atarsa — hepsinde sonuç
/// bir DURUM etiketidir, bir istisna değil. Kapı ileride açıldığında da bu ayrım korunmalı:
/// "ölçemedik" ile "sahte" aynı şey değildir, ve ölçülemeyen akışı reddetmek düz duvarın
/// önündeki meşru kullanıcıyı giriş yapamaz hale getirir.</para>
/// </summary>
public class PlanarityMeasurementServiceTests
{
    // --- Sentetik nokta üretimi: yalnız gözler-arası mesafe önemli (açıklık ondan çıkıyor) ---
    private const double FocalPx = 1400, Cx = 540, Cy = 960;

    private static float[] FaceAt(double distanceMm)
    {
        // Gözler ±31,5 mm; kalan noktalar açıklık hesabını etkilemez ama dizi 10 elemanlı olmalı.
        double[,] pts = { { -31.5, 0 }, { 31.5, 0 }, { 0, 36 }, { -25.7, 72.9 }, { 26.5, 72.6 } };
        var lm = new float[10];
        for (int i = 0; i < 5; i++)
        {
            lm[2 * i] = (float)(FocalPx * pts[i, 0] / distanceMm + Cx);
            lm[2 * i + 1] = (float)(FocalPx * pts[i, 1] / distanceMm + Cy);
        }
        return lm;
    }

    private static ParallaxProof Proof(int frames, double? texture = 50.0, bool complete = true)
    {
        string f = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 });
        return new ParallaxProof
        {
            Frames = Enumerable.Repeat(f, frames).ToList(),
            BgTexture = texture,
            Complete = complete,
            ElapsedMs = 7000,
        };
    }

    /// <summary>Kareler en uzaktan en yakına sıralı: mesafe azalır, yüz büyür.</summary>
    private static Mock<IBiometricService> Detector(params double[] distancesMm)
    {
        var mock = new Mock<IBiometricService>();
        int call = 0;
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>()))
            .Returns(() => FaceAt(distancesMm[Math.Min(call++, distancesMm.Length - 1)]));
        return mock;
    }

    // =========================================================================================

    [Fact]
    public void NoProof_ReturnsNoProofStatus_WithoutTouchingDetector()
    {
        var detector = new Mock<IBiometricService>(MockBehavior.Strict);
        var svc = new PlanarityMeasurementService(detector.Object);

        Assert.Equal("no_proof", svc.Measure(null).Status);
        Assert.Equal("no_proof", svc.Measure(new ParallaxProof()).Status);

        detector.Verify(b => b.DetectLandmarks(It.IsAny<byte[]>()), Times.Never);
    }

    /// <summary>Dört mesafe, gerçek bir yaklaşma → ölçüldü, açıklık raporlandı.</summary>
    [Fact]
    public void FullProof_ReportsSpanMeasuredByUs()
    {
        var svc = new PlanarityMeasurementService(Detector(600, 500, 400, 300).Object);
        PlanarityOutcome o = svc.Measure(Proof(4));

        Assert.Equal("measured", o.Status);
        Assert.Equal(4, o.FarMeasured);
        // 600 → 300 mm = yüz iki katı büyür.
        Assert.NotNull(o.IedRatio);
        Assert.True(Math.Abs(o.IedRatio!.Value - 2.0) < 0.05, $"açıklık={o.IedRatio}");
    }

    /// <summary>
    /// 🔴 Açıklık istemciden ALINMAZ, biz ölçeriz. İstemcinin beyanı doğrulanamaz ve açıklık
    /// sinyalin anlamını belirleyen sayıdır.
    /// </summary>
    [Fact]
    public void Span_IsMeasuredByUs_NotTakenFromClient()
    {
        var proof = Proof(4);
        proof.SpanRatio = 99.0;                     // istemci saçmalıyor

        var o = new PlanarityMeasurementService(Detector(600, 500, 400, 300).Object).Measure(proof);

        Assert.True(o.IedRatio < 3.0, $"istemcinin beyanı sızmış: {o.IedRatio}");
    }

    /// <summary>Kullanıcı yeterince yaklaşmadıysa sinyalin anlamı yok — ayrı etiket.</summary>
    [Fact]
    public void TooLittleApproach_IsLabelledNotApproached()
    {
        var svc = new PlanarityMeasurementService(Detector(600, 580, 560, 550).Object);
        Assert.Equal("not_approached", svc.Measure(Proof(4)).Status);
    }

    /// <summary>
    /// Dokusuz arka plan AYRI etiketlenir — ve bu bir RED sebebi değildir.
    /// Düz duvarın önündeki meşru kullanıcı giriş yapamaz hale gelmemeli.
    /// </summary>
    [Fact]
    public void NoBackgroundTexture_IsLabelledSeparately_NotRejected()
    {
        var svc = new PlanarityMeasurementService(Detector(600, 500, 400, 300).Object);
        var o = svc.Measure(Proof(4, texture: 5.0));

        Assert.Equal("no_texture", o.Status);
        Assert.NotNull(o.IedRatio);                 // veri yine de toplanır
    }

    [Fact]
    public void NoFaceDetected_IsReported()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>())).Returns((float[]?)null);

        var o = new PlanarityMeasurementService(mock.Object).Measure(Proof(4));

        Assert.Equal("no_face_far", o.Status);
        Assert.Equal(0, o.FarMeasured);
        Assert.Null(o.IedRatio);
    }

    [Fact]
    public void CorruptFrame_IsSkipped_NotFatal()
    {
        var proof = Proof(4);
        proof.Frames[1] = "bu-base64-değil!!!";

        var o = new PlanarityMeasurementService(Detector(600, 450, 300).Object).Measure(proof);

        Assert.Equal(3, o.FarMeasured);
        Assert.Equal("measured", o.Status);
    }

    /// <summary>Şişirilmiş kare işlenmez — register ucuz bir CPU tüketim yüzeyi olmamalı.</summary>
    [Fact]
    public void OversizedFrame_IsSkipped()
    {
        var proof = Proof(4);
        proof.Frames[0] = Convert.ToBase64String(new byte[500_000]);

        var detector = Detector(600, 450, 300);
        new PlanarityMeasurementService(detector.Object).Measure(proof);

        detector.Verify(b => b.DetectLandmarks(It.Is<byte[]>(a => a.Length > 400_000)), Times.Never);
    }

    [Fact]
    public void FrameCount_IsCapped()
    {
        var detector = Detector(600, 500, 400, 300);
        new PlanarityMeasurementService(detector.Object).Measure(Proof(50));

        detector.Verify(b => b.DetectLandmarks(It.IsAny<byte[]>()),
            Times.Exactly(PlanarityMeasurementService.MaxFrames));
    }

    /// <summary>
    /// 🔴 Dedektör patlasa bile ölçüm istisna FIRLATMAZ — sözleşmenin en sert hâli.
    /// </summary>
    [Fact]
    public void DetectorThrowing_DoesNotPropagate()
    {
        var mock = new Mock<IBiometricService>();
        mock.Setup(b => b.DetectLandmarks(It.IsAny<byte[]>()))
            .Throws(new InvalidOperationException("model yok"));

        var o = new PlanarityMeasurementService(mock.Object).Measure(Proof(4));

        Assert.Equal("no_face_far", o.Status);
        Assert.Null(o.Delta);
    }

    /// <summary>
    /// Asıl sinyal (yüz/arka plan ölçek oranı) bu sürümde HENÜZ hesaplanmıyor: arka planın
    /// ölçeğini çıkarmak gerçek özellik eşleştirmesi (ORB) gerektiriyor ve o yazılmadı.
    /// Bu testin görevi beklentiyi kayda geçirmek — biri "delta neden hep boş" diye sorunca
    /// cevabı burada bulsun.
    /// </summary>
    [Fact]
    public void Delta_IsNotComputedYet_PendingFeatureMatching()
    {
        var o = new PlanarityMeasurementService(Detector(600, 500, 400, 300).Object).Measure(Proof(4));

        Assert.Equal("measured", o.Status);
        Assert.Null(o.Delta);
    }
}
