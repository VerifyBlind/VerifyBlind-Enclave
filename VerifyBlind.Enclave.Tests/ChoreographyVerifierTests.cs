using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Moq;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.Stance;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Duruş + olay doğrulamasının UÇTAN UCA sözleşmesi.
///
/// <para>Kareler GERÇEK JPEG: sahne yordamsal çiziliyor (dünya koordinatlarında dikdörtgenler),
/// yüz ve arka plan ayrı ölçeklerle — gerçek bir kafa ile düz bir ekran arasındaki tek fark
/// tam olarak bu. YuNet ve ArcFace sahte: noktalar sahnenin yüz ölçeğinden, gömme vektörü
/// karenin "kimden geldiği" etiketinden üretiliyor. Yani test, ORB'u ve karar zincirini gerçek
/// pikseller üzerinde, modelleri ise kontrollü girdiyle sınıyor.</para>
/// </summary>
public class ChoreographyVerifierTests
{
    private const int W = 360, H = 480;

    private static readonly Blob[] BgBlobs = MakeBlobs(0xB6_1105, 1100, 330);
    private static readonly Blob[] FaceBlobs = MakeBlobs(0xFACE_01, 70, 34);

    /// <summary>Başka bir oda: yakın karede arka planın eşleşmediği durumu kurmak için.</summary>
    private static readonly Blob[] AltBgBlobs = MakeBlobs(0x0DD_BA11, 1100, 330);

    private readonly record struct Blob(double X, double Y, double W, double H, byte V1, byte V2);

    private static Blob[] MakeBlobs(uint seed, int count, int spread)
    {
        uint s = seed;
        uint Next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
        var blobs = new Blob[count];
        for (int i = 0; i < count; i++)
            blobs[i] = new Blob(
                (int)(Next() % (uint)(2 * spread)) - spread,
                (int)(Next() % (uint)(2 * spread)) - spread,
                3 + Next() % 11, 3 + Next() % 11,
                (byte)(25 + Next() % 205), (byte)(25 + Next() % 205));
        return blobs;
    }

    /// <summary>Göz-arası mesafe = 28 × yüz ölçeği: yüz kutusu (1,5 × göz-arası) yüz desenini örter.</summary>
    private const double IodPerScale = 28;

    /// <summary>
    /// Sahneyi çizip JPEG'e kodlar. <paramref name="jitter"/> px kadar kaydırma: elde tutulan
    /// telefonun titremesi (0 = donmuş kare).
    /// </summary>
    private static byte[] RenderJpeg(double bgScale, double faceScale, double jitter = 0, bool altBackground = false)
    {
        var px = new byte[W * H];
        double phase = altBackground ? 2.1 : 0;
        for (int y = 0; y < H; y++)
            for (int x = 0; x < W; x++)
            {
                double wx = (x - W / 2.0 - jitter) / bgScale, wy = (y - H / 2.0) / bgScale;
                double v = 110 + 38 * Math.Sin(wx / 53.0 + phase) + 32 * Math.Cos(wy / 41.0 + phase)
                               + 24 * Math.Sin((wx + wy) / 71.0 + phase);
                px[y * W + x] = (byte)Math.Clamp(v, 0, 255);
            }

        void Draw(Blob[] blobs, double scale)
        {
            foreach (var b in blobs)
            {
                double cx = W / 2.0 + jitter + b.X * scale, cy = H / 2.0 + b.Y * scale;
                double hw = b.W * scale / 2, hh = b.H * scale / 2;
                int x0 = (int)Math.Max(0, cx - hw), x1 = (int)Math.Min(W - 1, cx + hw);
                int y0 = (int)Math.Max(0, cy - hh), y1 = (int)Math.Min(H - 1, cy + hh);
                for (int y = y0; y <= y1; y++)
                    for (int x = x0; x <= x1; x++)
                        px[y * W + x] = x < cx ? b.V1 : b.V2;
            }
        }

        Draw(altBackground ? AltBgBlobs : BgBlobs, bgScale);
        Draw(FaceBlobs, faceScale);

        using var img = Image.LoadPixelData<L8>(px, W, H);
        using var ms = new MemoryStream();
        img.SaveAsJpeg(ms, new JpegEncoder { Quality = 95 });
        return ms.ToArray();
    }

    private static float[] Landmarks(double faceScale, double jitter = 0)
    {
        double iod = IodPerScale * faceScale;
        double cx = W / 2.0 + jitter, cy = H / 2.0;
        return new[]
        {
            (float)(cx - iod / 2), (float)(cy - iod / 2),
            (float)(cx + iod / 2), (float)(cy - iod / 2),
            (float)cx, (float)cy,
            (float)(cx - 0.4 * iod), (float)(cy + 0.6 * iod),
            (float)(cx + 0.4 * iod), (float)(cy + 0.6 * iod),
        };
    }

    /// <summary>Test sahnesi: kare → (yüz ölçeği, kimden geldiği).</summary>
    private sealed class Scene
    {
        private readonly Dictionary<string, (double scale, double jitter, string who)> _frames = new();

        public string Add(double bgScale, double faceScale, string who = "victim", double jitter = 0,
            bool altBackground = false)
        {
            var bytes = RenderJpeg(bgScale, faceScale, jitter, altBackground);
            var b64 = Convert.ToBase64String(bytes);
            _frames[b64] = (faceScale, jitter, who);
            return b64;
        }

        public Mock<IBiometricService> Models()
        {
            var mock = new Mock<IBiometricService>();
            mock.SetupGet(b => b.IsModelLoaded).Returns(true);
            mock.Setup(b => b.DetectFace(It.IsAny<byte[]>())).Returns((byte[] bytes) =>
            {
                if (!_frames.TryGetValue(Convert.ToBase64String(bytes), out var f)) return null;
                var lm = Landmarks(f.scale, f.jitter);
                double iod = IodPerScale * f.scale;
                return new FaceObservation(lm, (float)(W / 2.0 - 1.4 * iod), (float)(H / 2.0 - 1.6 * iod),
                    (float)(2.8 * iod), (float)(3.4 * iod), W, H);
            });
            // Kimlik fotoğrafı "victim" vektörü; kareler etiketlerine göre.
            mock.Setup(b => b.ComputeEmbedding(It.IsAny<byte[]>())).Returns(Vector("victim"));
            mock.Setup(b => b.ComputeEmbedding(It.IsAny<byte[]>(), It.IsAny<float[]>()))
                .Returns((byte[] bytes, float[] _) =>
                    Vector(_frames.TryGetValue(Convert.ToBase64String(bytes), out var f) ? f.who : "none"));
            mock.Setup(b => b.CosineSimilarity(It.IsAny<float[]>(), It.IsAny<float[]>()))
                .Returns((float[] a, float[] b) => a.Zip(b, (x, y) => x * y).Sum());
            return mock;
        }

        private static float[] Vector(string who) => who switch
        {
            "victim" => new[] { 1f, 0f, 0f },
            "attacker" => new[] { 0f, 1f, 0f },
            _ => new[] { 0f, 0f, 1f },
        };
    }

    /// <summary>
    /// Arka plan yüzün 3 katı uzakta (g = 3N): yüz s kat büyürken arka plan (s+3)/4 kat büyür.
    /// s = 2'de B = 1,6, P = 0,6 — sahada meşru koşuların bandı.
    /// </summary>
    private static double RealBackground(double faceScale) => (faceScale + 3) / 4;

    private static readonly Dictionary<StancePosition, double> ScaleOf = new()
    {
        [StancePosition.Far] = 1.0,
        [StancePosition.Mid] = Math.Sqrt(2.0),
        [StancePosition.Near] = 2.0,
    };

    private static Choreography Demand(params (StancePosition pos, StanceEvent ev)[] stops) => new()
    {
        Version = 1,
        Stops = stops.Select(s => new ChoreographyStop { Position = s.pos, Event = s.ev }).ToList(),
    };

    /// <summary>N · F+kırpma · M · N+gülümseme — dört duraklı tipik bir dizi.</summary>
    private static readonly Choreography Typical = Demand(
        (StancePosition.Near, StanceEvent.None),
        (StancePosition.Far, StanceEvent.Blink),
        (StancePosition.Mid, StanceEvent.None),
        (StancePosition.Near, StanceEvent.Smile));

    /// <summary>Diziyi sahneden kurar: her durakta iki duruş karesi (titrek), olay duraklarında olay karesi.</summary>
    private static ChoreographyProof Perform(Scene scene, Choreography demanded,
        Func<int, double, (double bg, double face)> geometry, Func<int, string>? who = null,
        double jitter = 2.0)
    {
        var proof = new ChoreographyProof { Version = 1, BgTexture = 30, ElapsedMs = 14000, Resets = 0, WrongEvents = 0 };
        for (int i = 0; i < demanded.Stops.Count; i++)
        {
            var stop = demanded.Stops[i];
            var (bg, face) = geometry(i, ScaleOf[stop.Position]);
            string person = who?.Invoke(i) ?? "victim";
            var sent = new ChoreographyProofStop
            {
                Hold = { scene.Add(bg, face, person), scene.Add(bg, face, person, jitter) },
            };
            int events = stop.Event switch { StanceEvent.None => 0, StanceEvent.DoubleBlink => 2, _ => 1 };
            for (int e = 0; e < events; e++) sent.Event.Add(scene.Add(bg, face, person, jitter / 2 + e));
            proof.Stops.Add(sent);
        }
        return proof;
    }

    private static (double bg, double face) Real(int _, double s) => (RealBackground(s), s);
    private static (double bg, double face) Flat(int _, double s) => (s, s);

    // ── Yapı ─────────────────────────────────────────────────────────────────

    [Fact]
    public void YapiKurallari()
    {
        var scene = new Scene();
        var ok = Perform(scene, Typical, Real);
        Assert.Null(ChoreographyVerifier.ValidateStructure(ok, Typical));

        var badVersion = Perform(scene, Typical, Real); badVersion.Version = 2;
        Assert.Equal("version", ChoreographyVerifier.ValidateStructure(badVersion, Typical));

        var missingStop = Perform(scene, Typical, Real); missingStop.Stops.RemoveAt(3);
        Assert.Equal("stops", ChoreographyVerifier.ValidateStructure(missingStop, Typical));

        var noHold = Perform(scene, Typical, Real); noHold.Stops[2].Hold.Clear();
        Assert.Equal("hold", ChoreographyVerifier.ValidateStructure(noHold, Typical));

        var threeHolds = Perform(scene, Typical, Real); threeHolds.Stops[0].Hold.Add(threeHolds.Stops[0].Hold[0]);
        Assert.Equal("hold", ChoreographyVerifier.ValidateStructure(threeHolds, Typical));

        var missingEvent = Perform(scene, Typical, Real); missingEvent.Stops[1].Event.Clear();
        Assert.Equal("event", ChoreographyVerifier.ValidateStructure(missingEvent, Typical));

        // Olaysız durakta olay karesi de bozuk yapı.
        var extraEvent = Perform(scene, Typical, Real); extraEvent.Stops[0].Event.Add(extraEvent.Stops[0].Hold[0]);
        Assert.Equal("event", ChoreographyVerifier.ValidateStructure(extraEvent, Typical));
    }

    [Fact]
    public void CiftKirpmaIkiOlayKaresiIster()
    {
        var demanded = Demand(
            (StancePosition.Near, StanceEvent.DoubleBlink), (StancePosition.Far, StanceEvent.None),
            (StancePosition.Mid, StanceEvent.MouthOpen), (StancePosition.Far, StanceEvent.None));
        var scene = new Scene();
        var proof = Perform(scene, demanded, Real);
        Assert.Null(ChoreographyVerifier.ValidateStructure(proof, demanded));

        proof.Stops[0].Event.RemoveAt(1);
        Assert.Equal("event", ChoreographyVerifier.ValidateStructure(proof, demanded));
    }

    [Fact]
    public void CozulemeyenKareYapiyiBozar()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real);
        proof.Stops[2].Hold[1] = "bu-base64-degil!";

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(ChoreographyVerifier.StatusInvalid, o.Choreography!.Status);
        Assert.Equal("frame", o.Choreography.InvalidReason);
        Assert.Equal(PlanarityStatuses.Unmeasured, o.Status);
    }

    // ── Meşru akış ───────────────────────────────────────────────────────────

    [Fact]
    public void MesruAkisOlculurVeKimlikTutar()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real);

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        var c = o.Choreography!;

        Assert.Equal(ChoreographyVerifier.StatusMeasured, c.Status);
        Assert.Equal(PlanarityStatuses.Measured, o.Status);
        Assert.True(o.NearResidual > PlanarityMeasurementService.MinParallaxP, $"P={o.NearResidual}");

        // Kimlik: her durağın ölçüm karesi, dört durak.
        Assert.Equal(4, c.Identity!.Count);
        Assert.Equal(1.0, c.IdentityMin!.Value, 3);
        Assert.Equal(2, c.EventIdentity!.Count);

        // Konum: ölçülen ölçek değişimi istenenle aynı → hata ~0.
        Assert.True(c.PositionErrMax < 0.02, $"hata={c.PositionErrMax}");
        Assert.Equal(new[] { 2.0, 1.0, 1.414, 2.0 }, c.StopScales!.Select(v => Math.Round(v, 3)).ToArray());

        // Titreşim var (2 px kaydırma), donmuş kare değil.
        Assert.True(c.HoldMotionMin > 1.0, $"titreşim={c.HoldMotionMin}");

        // Uzak↔yakın ve orta↔uzak/yakın çiftlerinin hepsi yeterince geniş ve tutuyor.
        Assert.True(c.ParallaxPairs >= PlanarityMeasurementService.MinStrictPairs, $"çift={c.ParallaxPairs}");

        Assert.Equal("N,F+blink,M,N+smile", c.Demanded);
        Assert.Equal(10, c.Frames);
        Assert.Equal(10, c.Faces);
        Assert.Equal(2, c.Events!.Count);
    }

    // ── Saldırılar ───────────────────────────────────────────────────────────

    /// <summary>Düz yüzey: yüz ve arka plan aynı oranda büyür → P ≈ 0.</summary>
    [Fact]
    public void DuzYuzeyDuzOlculur()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Flat);

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(PlanarityStatuses.FlatSurface, o.Status);
        Assert.True(o.NearResidual < 0.1, $"P={o.NearResidual}");
    }

    /// <summary>
    /// 🔴 KAYNAK AYRIMI: derinliği saldırganın kendi kafası sağlıyor. Parallaks GEÇER ama
    /// duruş karelerindeki yüz kart sahibi değil → kimlik en küçüğü düşer.
    /// </summary>
    [Fact]
    public void KaynakAyrimiKimliktenYakalanir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real, who: i => i == 1 ? "attacker" : "victim");

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(PlanarityStatuses.Measured, o.Status);
        Assert.Equal(0.0, o.Choreography!.IdentityMin!.Value, 3);
        Assert.Equal(1.0, o.Choreography.Identity![0], 3);
    }

    /// <summary>
    /// Hareketsiz kareler (yamalanmış istemci ya da hareket etmeyen kullanıcı): P hesaplanamaz.
    /// Eski kanıtta bu "ölçemedik → geç" idi; duruş kanıtında RED sebebi.
    /// </summary>
    [Fact]
    public void HareketsizDiziOlculemezSayilir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, (_, _) => (1.0, 1.0));

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(PlanarityStatuses.Unmeasured, o.Status);
    }

    /// <summary>
    /// Kullanıcı mesafeleri yalnız kısmen uyguladı: en geniş çift bile 1,25'in altında. Dar
    /// çiftin P'si gürültüdür (1,16'da ±0,19) — gerçek bir sahne olsa da ölçülmüş sayılmaz.
    /// </summary>
    [Fact]
    public void DarCiftlerPyeGirmez()
    {
        var scene = new Scene();
        var narrow = new Dictionary<StancePosition, double>
        {
            [StancePosition.Far] = 1.0, [StancePosition.Mid] = 1.1, [StancePosition.Near] = 1.2,
        };
        var proof = Perform(scene, Typical, (i, _) =>
        {
            double s = narrow[Typical.Stops[i].Position];
            return (RealBackground(s), s);
        });

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(PlanarityStatuses.Unmeasured, o.Status);
        Assert.Equal(0, o.Choreography!.ParallaxPairs);
    }

    /// <summary>
    /// 🔴 SIRTI PERDEDE (2026-09-24 14:52): yakın karelerde arka plan eşleşmiyor, geriye tek
    /// uzak↔orta çifti kalıyor. Sahada o tek çift eşiği 0,003 farkla geçirdi. Tek çift bir
    /// ölçüm değil — sonuç "ölçülemedi", yani red ve "bir adım uzaklaşın".
    /// </summary>
    [Fact]
    public void TekCiftYetmez()
    {
        var scene = new Scene();
        var proof = new ChoreographyProof { Version = 1, BgTexture = 18, ElapsedMs = 14000 };
        for (int i = 0; i < Typical.Stops.Count; i++)
        {
            var stop = Typical.Stops[i];
            double s = ScaleOf[stop.Position];
            bool near = stop.Position == StancePosition.Near;   // yakında arka plan eşleşmiyor
            var sent = new ChoreographyProofStop
            {
                Hold =
                {
                    scene.Add(RealBackground(s), s, altBackground: near),
                    scene.Add(RealBackground(s), s, jitter: 2, altBackground: near),
                },
            };
            if (stop.Event != StanceEvent.None)
                sent.Event.Add(scene.Add(RealBackground(s), s, jitter: 1, altBackground: near));
            proof.Stops.Add(sent);
        }

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(1, o.Choreography!.ParallaxPairs);
        Assert.Equal(PlanarityStatuses.Unmeasured, o.Status);
        // Mesaj seçimi dokudan: desen var (18) → "arka plan çok yakın, bir adım uzaklaşın".
        Assert.Equal(VerifyBlind.Core.EnclaveErrorCodes.ParallaxFlat, EnclaveService.StanceGate(o)!.ErrorCode);
    }

    /// <summary>
    /// Uzak↔orta çiftleri bol (dört tane, hepsi 1,41) ama YAKIN kareler hiçbir şeyle eşleşmiyor.
    /// Çift sayısı yeterli, en geniş tutan çift değil: arka plan yakın uçta ölçülemedi demek —
    /// sahadaki sırt-yüzeyde koşularının 8/8'inin imzası.
    /// </summary>
    [Fact]
    public void UzakYakinCiftiTutmazsaOlculemez()
    {
        var demanded = Demand(
            (StancePosition.Near, StanceEvent.None), (StancePosition.Far, StanceEvent.Blink),
            (StancePosition.Mid, StanceEvent.None), (StancePosition.Far, StanceEvent.None),
            (StancePosition.Mid, StanceEvent.Smile));
        var scene = new Scene();
        var proof = new ChoreographyProof { Version = 1, BgTexture = 18, ElapsedMs = 16000 };
        for (int i = 0; i < demanded.Stops.Count; i++)
        {
            var stop = demanded.Stops[i];
            double s = ScaleOf[stop.Position];
            bool near = stop.Position == StancePosition.Near;
            var sent = new ChoreographyProofStop
            {
                Hold =
                {
                    scene.Add(RealBackground(s), s, altBackground: near),
                    scene.Add(RealBackground(s), s, jitter: 2, altBackground: near),
                },
            };
            if (stop.Event != StanceEvent.None)
                sent.Event.Add(scene.Add(RealBackground(s), s, jitter: 1, altBackground: near));
            proof.Stops.Add(sent);
        }

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, demanded, new byte[] { 1 });
        Assert.True(o.Choreography!.ParallaxPairs >= PlanarityMeasurementService.MinStrictPairs,
            $"çift={o.Choreography.ParallaxPairs}");
        Assert.True(o.FarResidual < PlanarityMeasurementService.MinStrictWidestSpan, $"s={o.FarResidual}");
        Assert.Equal(PlanarityStatuses.Unmeasured, o.Status);
    }

    /// <summary>
    /// Donmuş kare: iki duruş karesi birebir aynı. Elde tutulan telefonda olmaz — ölçü sıfıra düşer.
    /// </summary>
    [Fact]
    public void DonmusKareTitresimSifir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real, jitter: 0);

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(0.0, o.Choreography!.HoldMotionMin!.Value, 3);
    }

    /// <summary>Yüz bulunamayan durak 0 sayılır: "yüz yok" karesiyle kimlik kapısı atlatılamaz.</summary>
    [Fact]
    public void YuzsuzDurakKimlikteSifirSayilir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real);
        var models = scene.Models();
        var faceless = new HashSet<string>(proof.Stops[2].Hold);
        models.Setup(b => b.DetectFace(It.Is<byte[]>(x => faceless.Contains(Convert.ToBase64String(x)))))
              .Returns((FaceObservation?)null);

        var o = new ChoreographyVerifier(models.Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(0.0, o.Choreography!.IdentityMin!.Value, 3);
    }

    [Fact]
    public void KimlikFotografiYoksaKimlikOlculmez()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real);

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, idPhotoBytes: null);
        Assert.Null(o.Choreography!.Identity);
        Assert.Null(o.Choreography.IdentityMin);
    }

    /// <summary>Kontur: sahte YuNet kutusu göz-arasıyla orantılı → oran 1 (düz yüzeyin imzası).</summary>
    [Fact]
    public void KonturOraniOlculur()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, Real);

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(2.8, o.Choreography!.ContourFar!.Value, 2);
        Assert.Equal(1.0, o.Choreography.ContourRatio!.Value, 3);
    }
}
