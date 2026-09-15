using System;
using VerifyBlind.Enclave.Services.FaceAlignment;
using Xunit;
using Xunit.Abstractions;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Düzlem-dışılık sınamasının FİZİĞİNİ sentetik veriyle doğrular — telefonla tek bir test
/// yapılmadan önce.
///
/// <para><b>Neden sentetik:</b> <see cref="PlanarityProbe"/> saf geometridir. "Gerçek yüz ile
/// ekran, kamera yaklaşınca ayrışır mı?" sorusu bir pinhole kamera modeliyle burada
/// cevaplanabilir. Ayrışmıyorsa cihazda denemenin anlamı yok; ayrışıyorsa cihaz testi yalnız
/// GERÇEK DÜNYA GÜRÜLTÜSÜNÜ ölçer.</para>
///
/// <para><b>Asıl güvenlik özelliği (bkz. <see cref="PlanarMotion_OfAnyKind_ProducesNoSignal"/>):</b>
/// düzlemsel bir nesnenin HİÇBİR katı hareketi sinyal üretemez. Ötelemesi, eğilmesi, dönmesi
/// hepsi homografidir ve homografiler bileşiktir → burun artığı sabit kalır. Yani saldırgan
/// monitörü nasıl oynatırsa oynatsın "3B" gibi görünemez. Bu, doku modelinden farklı olarak bir
/// MODEL HÜKMÜ değil, projektif geometrinin sonucudur.</para>
/// </summary>
public class PlanarityProbeTests
{
    private readonly ITestOutputHelper _out;

    public PlanarityProbeTests(ITestOutputHelper output) => _out = output;

    // --- Kamera modeli (tipik ön kamera) ---
    private const double FocalPx = 1400;   // 1080 px genişlikte ~65° yatay görüş açısı
    private const double Cx = 540, Cy = 960;

    // --- 3B yüz modeli (mm, orijin gözlerin ortası, +y aşağı, +z kameradan UZAK) ---
    // Kanonik ArcFace şablonundan ölçeklendi: gerçek gözler-arası ≈ 63 mm.
    // Burun ucu, gözler+ağız köşelerinin düzleminin ~20 mm ÖNÜNDE (bu yüzden z negatif).
    private const double NoseProtrusionMm = 20.0;

    private static double[,] FaceModel3D(double noseZ) => new[,]
    {
        { -31.50,   0.17, 0.0    },   // sağ göz
        {  31.50,  -0.17, 0.0    },   // sol göz
        {   0.20,  36.00, noseZ  },   // burun ucu
        { -25.70,  72.90, 0.0    },   // sağ ağız köşesi
        {  26.50,  72.60, 0.0    },   // sol ağız köşesi
    };

    /// <summary>3B noktaları piksel düzlemine izdüşürür (pinhole).</summary>
    private static float[] Project(double[,] pts3d, double distanceMm,
        double yawRad = 0, double rollRad = 0, double offsetXMm = 0, double offsetYMm = 0)
    {
        var lm = new float[10];
        for (int i = 0; i < 5; i++)
        {
            double x = pts3d[i, 0], y = pts3d[i, 1], z = pts3d[i, 2];

            // Y ekseni etrafında dönme (yaw)
            double xr = x * Math.Cos(yawRad) + z * Math.Sin(yawRad);
            double zr = -x * Math.Sin(yawRad) + z * Math.Cos(yawRad);

            // Z ekseni etrafında dönme (roll — görüntü düzleminde eğiklik)
            double xf = xr * Math.Cos(rollRad) - y * Math.Sin(rollRad);
            double yf = xr * Math.Sin(rollRad) + y * Math.Cos(rollRad);

            double wz = distanceMm + zr;
            lm[2 * i]     = (float)(FocalPx * (xf + offsetXMm) / wz + Cx);
            lm[2 * i + 1] = (float)(FocalPx * (yf + offsetYMm) / wz + Cy);
        }
        return lm;
    }

    /// <summary>
    /// "Monitör" modeli: gerçek bir yüz bir kez <paramref name="photoDistanceMm"/>'den çekilir,
    /// çıkan 2B görüntü DÜZ bir yüzey olarak sahneye konur ve oradan izdüşürülür.
    ///
    /// Fotoğrafın kendi perspektifi görüntüye GÖMÜLÜDÜR (burun zaten biraz büyük çıkmıştır) —
    /// gerçekçi olan budur; saldırgan düz bir fotoğraf değil, yüz fotoğrafı gösteriyor.
    /// </summary>
    private static float[] ProjectScreen(double screenDistanceMm, double photoDistanceMm,
        double tiltRad = 0, double mmPerPhotoPx = 0.35, double offsetXMm = 0)
    {
        float[] photo = Project(FaceModel3D(-NoseProtrusionMm), photoDistanceMm);

        // Fotoğraf piksellerini ekran üzerinde fiziksel mm'ye taşı (düzlem: z = 0 yerel).
        var plane = new double[5, 3];
        for (int i = 0; i < 5; i++)
        {
            plane[i, 0] = (photo[2 * i] - Cx) * mmPerPhotoPx;
            plane[i, 1] = (photo[2 * i + 1] - Cy) * mmPerPhotoPx;
            plane[i, 2] = 0;
        }

        return Project(plane, screenDistanceMm, yawRad: tiltRad, offsetXMm: offsetXMm);
    }

    // =========================================================================================
    // 1. ASIL SORU: gerçek yüz ile ekran ayrışıyor mu?
    // =========================================================================================

    /// <summary>
    /// GERÇEK YÜZ, 60 cm → 25 cm: burun artığı DEĞİŞİR. Sinyalin büyüklüğü buradan okunur.
    /// </summary>
    [Fact]
    public void RealFace_MovingCloser_ChangesNoseResidual()
    {
        float[] far = Project(FaceModel3D(-NoseProtrusionMm), 600);
        float[] near = Project(FaceModel3D(-NoseProtrusionMm), 250);

        double? rFar = PlanarityProbe.NoseResidual(far);
        double? rNear = PlanarityProbe.NoseResidual(near);
        double? delta = PlanarityProbe.Delta(far, near);

        _out.WriteLine($"GERÇEK YÜZ  uzak={rFar:F5}  yakın={rNear:F5}  delta={delta:F5}");

        Assert.NotNull(delta);
        Assert.True(delta > 0.01,
            $"Gerçek yüz 60→25 cm'de ölçülebilir sinyal üretmeli, delta={delta:F5}");
    }

    /// <summary>
    /// EKRAN, aynı mesafe değişimi: burun artığı SABİT kalır → sinyal ~0.
    /// Bu, tüm fikrin dayandığı ayrım.
    /// </summary>
    [Fact]
    public void Screen_MovingCloser_ProducesNoSignal()
    {
        float[] far = ProjectScreen(600, photoDistanceMm: 800);
        float[] near = ProjectScreen(250, photoDistanceMm: 800);

        double? rFar = PlanarityProbe.NoseResidual(far);
        double? rNear = PlanarityProbe.NoseResidual(near);
        double? delta = PlanarityProbe.Delta(far, near);

        _out.WriteLine($"EKRAN       uzak={rFar:F5}  yakın={rNear:F5}  delta={delta:F5}");

        Assert.NotNull(delta);
        Assert.True(delta < 0.001,
            $"Düz ekran mesafe değişiminde sinyal ÜRETMEMELİ, delta={delta:F5}");
    }

    /// <summary>
    /// İkisini yan yana koyar: gerçek yüzün sinyali ekranınkinden en az bir büyüklük mertebesi
    /// fazla olmalı. Ayrışma oranı = bu testin asıl çıktısı.
    /// </summary>
    [Fact]
    public void RealFace_SeparatesFromScreen_ByWideMargin()
    {
        double faceDelta = PlanarityProbe.Delta(
            Project(FaceModel3D(-NoseProtrusionMm), 600),
            Project(FaceModel3D(-NoseProtrusionMm), 250))!.Value;

        double screenDelta = PlanarityProbe.Delta(
            ProjectScreen(600, 800),
            ProjectScreen(250, 800))!.Value;

        _out.WriteLine($"AYRIŞMA     yüz={faceDelta:F5}  ekran={screenDelta:F5}  " +
                       $"oran={(screenDelta > 1e-9 ? faceDelta / screenDelta : double.PositiveInfinity):F1}x");

        Assert.True(faceDelta > screenDelta * 10,
            $"Ayrışma yetersiz: yüz={faceDelta:F5} ekran={screenDelta:F5}");
    }

    // =========================================================================================
    // 2. GÜVENLİK ÖZELLİĞİ: düzlemsel nesne hiçbir hareketle sinyal üretemez
    // =========================================================================================

    /// <summary>
    /// Saldırgan monitörü eğse, kaydırsa, döndürse de sinyal üretemez — hepsi homografidir.
    /// Bu test "monitörü şöyle tutarsam kandırır mıyım" sorusunun cevabıdır: hayır.
    /// </summary>
    [Theory]
    [InlineData(0.0, 0.0)]                 // düz duruş
    [InlineData(0.35, 0.0)]                // ~20° yana eğik
    [InlineData(0.0, 60.0)]                // yana kaydırılmış
    [InlineData(0.52, -80.0)]              // ~30° eğik + kaydırılmış
    public void PlanarMotion_OfAnyKind_ProducesNoSignal(double tiltRad, double offsetXMm)
    {
        float[] far = ProjectScreen(600, 800, tiltRad: 0, offsetXMm: 0);
        float[] near = ProjectScreen(250, 800, tiltRad: tiltRad, offsetXMm: offsetXMm);

        double? delta = PlanarityProbe.Delta(far, near);
        _out.WriteLine($"DÜZLEM HAREKETİ eğim={tiltRad:F2} kayma={offsetXMm}mm → delta={delta:F6}");

        Assert.NotNull(delta);
        Assert.True(delta < 0.002,
            $"Düzlemsel hareket sinyal üretmemeli (eğim={tiltRad}, kayma={offsetXMm}), delta={delta:F6}");
    }

    // =========================================================================================
    // 3. MEŞRU KULLANICI: ölçüm sıradan değişkenliğe dayanmalı
    // =========================================================================================

    /// <summary>
    /// Görüntü düzlemindeki eğiklik (roll) burun artığını DEĞİŞTİRMEMELİ — homografi onu yutar.
    /// Aksi halde başını yana eğen meşru kullanıcı sinyal üretir ve ölçüm anlamsızlaşır.
    /// </summary>
    [Fact]
    public void HeadRoll_DoesNotChangeResidual()
    {
        double upright = PlanarityProbe.NoseResidual(
            Project(FaceModel3D(-NoseProtrusionMm), 500))!.Value;
        double rolled = PlanarityProbe.NoseResidual(
            Project(FaceModel3D(-NoseProtrusionMm), 500, rollRad: 0.30))!.Value;

        _out.WriteLine($"ROLL        dik={upright:F5}  eğik={rolled:F5}  fark={Math.Abs(upright - rolled):F6}");

        Assert.True(Math.Abs(upright - rolled) < 0.002,
            $"Roll artığı değiştirmemeli: dik={upright:F5} eğik={rolled:F5}");
    }

    /// <summary>
    /// Yüzün kadrajda nerede durduğu artığı DEĞİŞTİRİR — ve bu bir kusur değil, kazançtır.
    ///
    /// <para>İlk yazdığımda "kadraj artığı etkilememeli" diye varsaymıştım; ölçüm bunu çürüttü
    /// (orta 0,024 → kenar 0,068). Sebep fiziksel: burnun düzlem-dışı sapması ana noktadan
    /// RADYAL olarak izdüşer, dolayısıyla yüz kenara gittikçe parallaks artar.</para>
    ///
    /// <para>Ayrımı bozmaz çünkü DÜZLEMSEL nesnede kadraj konumu sinyali sıfırda tutar
    /// (bkz. <see cref="PlanarMotion_OfAnyKind_ProducesNoSignal"/>, kayma dahil → delta 0).
    /// Yani kadraj yalnız GERÇEK yüzün sinyalini büyütür. En kötü durum yüzün tam ortada
    /// olmasıdır; eşik ona göre seçilmeli.</para>
    /// </summary>
    [Fact]
    public void FaceOffCenter_IncreasesResidual_ForRealFaceOnly()
    {
        double centered = PlanarityProbe.NoseResidual(
            Project(FaceModel3D(-NoseProtrusionMm), 500))!.Value;
        double offset = PlanarityProbe.NoseResidual(
            Project(FaceModel3D(-NoseProtrusionMm), 500, offsetXMm: 70, offsetYMm: 40))!.Value;

        _out.WriteLine($"KADRAJ      orta={centered:F5}  kenar={offset:F5}");

        Assert.True(offset > centered,
            $"Kenardaki gerçek yüz DAHA ÇOK parallaks vermeli: orta={centered:F5} kenar={offset:F5}");

        // Düzlemsel nesnede aynı kayma hiçbir şey üretmez — ayrım bu yüzden bozulmaz.
        double screenCentered = PlanarityProbe.NoseResidual(ProjectScreen(500, 800))!.Value;
        double screenOffset = PlanarityProbe.NoseResidual(ProjectScreen(500, 800, offsetXMm: 70))!.Value;

        _out.WriteLine($"KADRAJ(EKR) orta={screenCentered:F5}  kenar={screenOffset:F5}");

        Assert.True(Math.Abs(screenCentered - screenOffset) < 0.001,
            "Ekranda kadraj konumu artığı değiştirmemeli — homografi onu yutar.");
    }

    /// <summary>
    /// 🔴 TEK KARE ÇİFTİ YETMEZ — bu testin kaydettiği asıl bulgu budur.
    ///
    /// <para>Sinyal gözler-arası mesafenin yalnız ~%3'ü. Gerçekçi nokta titremesi altında tek
    /// kare çiftiyle ayrışma çöküyor: 0,5 px'te ~%100, 1,5 px'te ~%73, 3 px'te şansın ALTINDA
    /// (ekranın gerçek sinyali 0 olduğu için gürültü onu yalnız YUKARI iter, yüzünkini ise iki
    /// yöne).</para>
    ///
    /// <para>Bu yüzden üretim yolu <see cref="PlanarityProbe.Delta(IReadOnlyList{float[]},
    /// IReadOnlyList{float[]})"/> ile ÇOK KARE kullanır. Buradaki sayılar beklentiyi kayda
    /// geçirir; cihaz testi bu tabloyla kıyaslanacak.</para>
    /// </summary>
    [Theory]
    [InlineData(0.5, 0.95)]   // ölçülen: %100,0
    [InlineData(1.5, 0.55)]   // ölçülen: %60,3
    [InlineData(3.0, 0.20)]   // ölçülen: %35,7 — şansın altında; büyüklük değil vektör olduğu için dürüst
    public void SinglePair_DegradesWithJitter_SoProductionUsesFrameSets(double jitterPx, double atLeast)
    {
        double rate = SeparationRate(jitterPx, framesPerWindow: 1);
        _out.WriteLine($"TEK ÇİFT    titreme={jitterPx}px → yüz>ekran oranı = {rate:P1}");

        Assert.True(rate >= atLeast,
            $"Tek çift {jitterPx}px'te beklenenin altında: {rate:P1} < {atLeast:P0}");
    }

    /// <summary>
    /// ÇOK KARE medyanı ayrışmayı geri getirir — tasarım kararının gerekçesi.
    /// Aynı titremede tek çift %73'e düşerken 9'ar kare ile tekrar ayırt edilebilir olmalı.
    /// </summary>
    /// <summary>
    /// Beklenen oranlar ÖLÇÜLDÜ (sentetik). Bunlar cihaz testinin kıyas tablosudur:
    /// gerçek veride bu bandın çok altına düşersek gürültü varsayımımız yanlış demektir.
    /// </summary>
    [Theory]
    [InlineData(1.5, 9, 0.90)]    // ölçülen: %98,0
    [InlineData(3.0, 9, 0.60)]    // ölçülen: %69,8 — 3 px'te 9 kare YETMİYOR
    [InlineData(3.0, 15, 0.80)]   // ölçülen: %88,5 — 15 kare gerekiyor
    public void FrameSetMedian_RestoresSeparation(double jitterPx, int framesPerWindow, double atLeast)
    {
        double single = SeparationRate(jitterPx, 1);
        double many = SeparationRate(jitterPx, framesPerWindow);

        _out.WriteLine($"ÇOK KARE    titreme={jitterPx}px  tek={single:P1}  " +
                       $"{framesPerWindow}kare={many:P1}");

        Assert.True(many > single,
            $"Çok kare tek kareden iyi olmalı: {many:P1} ≤ {single:P1}");
        Assert.True(many >= atLeast,
            $"{framesPerWindow} kareyle ayrışma en az {atLeast:P0} olmalı, oran={many:P1}");
    }

    /// <summary>Gerçek yüz ile ekranı ayırt etme oranı — pencere başına N kare medyanıyla.</summary>
    private double SeparationRate(double jitterPx, int framesPerWindow)
    {
        var rng = new Random(20260915);
        int faceWins = 0;
        const int trials = 400;

        for (int t = 0; t < trials; t++)
        {
            double faceDelta = PlanarityProbe.Delta(
                Window(() => Project(FaceModel3D(-NoseProtrusionMm), 600), rng, jitterPx, framesPerWindow),
                Window(() => Project(FaceModel3D(-NoseProtrusionMm), 250), rng, jitterPx, framesPerWindow)) ?? 0;

            double screenDelta = PlanarityProbe.Delta(
                Window(() => ProjectScreen(600, 800), rng, jitterPx, framesPerWindow),
                Window(() => ProjectScreen(250, 800), rng, jitterPx, framesPerWindow)) ?? 0;

            if (faceDelta > screenDelta) faceWins++;
        }

        return faceWins / (double)trials;
    }

    private static List<float[]> Window(Func<float[]> frame, Random rng, double jitterPx, int count)
    {
        var list = new List<float[]>(count);
        for (int i = 0; i < count; i++) list.Add(Jitter(frame(), rng, jitterPx));
        return list;
    }

    private static float[] Jitter(float[] lm, Random rng, double sigmaPx)
    {
        var outLm = new float[lm.Length];
        for (int i = 0; i < lm.Length; i++)
        {
            // Box-Muller — düzgün değil normal gürültü; nokta titremesi gaussçuya yakındır.
            double u1 = 1.0 - rng.NextDouble(), u2 = rng.NextDouble();
            double g = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Cos(2.0 * Math.PI * u2);
            outLm[i] = (float)(lm[i] + g * sigmaPx);
        }
        return outLm;
    }

    // =========================================================================================
    // 4. BOZUK GİRDİ: ölçülemedi ≠ geçti / kaldı
    // =========================================================================================

    [Fact]
    public void NullOrWrongLength_ReturnsNull()
    {
        Assert.Null(PlanarityProbe.NoseResidual(null));
        Assert.Null(PlanarityProbe.NoseResidual(new float[8]));
        Assert.Null(PlanarityProbe.NoseResidual(new float[12]));
    }

    [Fact]
    public void CollapsedPoints_ReturnNull()
    {
        Assert.Null(PlanarityProbe.NoseResidual(new float[10]));   // hepsi (0,0)
    }

    [Fact]
    public void NaNInput_ReturnsNull()
    {
        float[] lm = Project(FaceModel3D(-NoseProtrusionMm), 500);
        lm[4] = float.NaN;
        Assert.Null(PlanarityProbe.NoseResidual(lm));
    }

    [Fact]
    public void Delta_WithOneUnmeasurableFrame_ReturnsNull()
    {
        float[] good = Project(FaceModel3D(-NoseProtrusionMm), 500);
        Assert.Null(PlanarityProbe.Delta(good, new float[10]));
        Assert.Null(PlanarityProbe.Delta(null, good));
    }

    /// <summary>
    /// Gözler-arası mesafe "gerçekten yaklaştı mı" kapısıdır; ekran da yaklaşınca büyür.
    /// Bu testin görevi o beklentiyi KAYDA GEÇİRMEK — sonradan biri onu sahtecilik ölçüsü
    /// sanmasın.
    /// </summary>
    [Fact]
    public void Interocular_GrowsForScreenToo_SoItIsNotASpoofSignal()
    {
        double farIed = PlanarityProbe.Interocular(ProjectScreen(600, 800))!.Value;
        double nearIed = PlanarityProbe.Interocular(ProjectScreen(250, 800))!.Value;

        _out.WriteLine($"IED (EKRAN) uzak={farIed:F1}px yakın={nearIed:F1}px oran={nearIed / farIed:F2}x");

        Assert.True(nearIed > farIed * 1.5,
            "Ekran da yaklaşınca büyür — IED oranı sahteciliği AYIRT ETMEZ, yalnız hareketi doğrular.");
    }
}
