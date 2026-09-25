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
using VerifyBlind.Enclave.Services.Liveness;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Olay dizisi doğrulamasının UÇTAN UCA sözleşmesi.
///
/// <para>Kareler GERÇEK JPEG (çözülebilir olmaları yapı kuralının parçası). YuNet ve ArcFace
/// sahte: noktalar sabit, gömme vektörü karenin "kimden geldiği" etiketinden üretiliyor. Yani
/// test karar zincirini — yapı, her karede kimlik, olay ölçümünün çalışması — kontrollü
/// girdiyle sınıyor.</para>
/// </summary>
public class ChoreographyVerifierTests
{
    private const int W = 320, H = 400;

    private static float[] Landmarks()
    {
        const double iod = 90, cx = W / 2.0, cy = H / 2.0;
        return new[]
        {
            (float)(cx - iod / 2), (float)(cy - iod / 2),
            (float)(cx + iod / 2), (float)(cy - iod / 2),
            (float)cx, (float)cy,
            (float)(cx - 0.4 * iod), (float)(cy + 0.6 * iod),
            (float)(cx + 0.4 * iod), (float)(cy + 0.6 * iod),
        };
    }

    /// <summary>Test sahnesi: kare → kimden geldiği. Her kare benzersiz (tohumlu gürültü).</summary>
    private sealed class Scene
    {
        private readonly Dictionary<string, string> _frames = new();
        private int _seed;

        public string Add(string who = "victim")
        {
            var px = new byte[W * H];
            uint s = (uint)(0x9E3779B9u * (uint)(++_seed));
            for (int i = 0; i < px.Length; i++) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; px[i] = (byte)(60 + s % 120); }
            using var img = Image.LoadPixelData<L8>(px, W, H);
            using var ms = new MemoryStream();
            img.SaveAsJpeg(ms, new JpegEncoder { Quality = 80 });
            var b64 = Convert.ToBase64String(ms.ToArray());
            _frames[b64] = who;
            return b64;
        }

        public Mock<IBiometricService> Models()
        {
            var mock = new Mock<IBiometricService>();
            mock.SetupGet(b => b.IsModelLoaded).Returns(true);
            mock.Setup(b => b.DetectFace(It.IsAny<byte[]>())).Returns((byte[] bytes) =>
                _frames.ContainsKey(Convert.ToBase64String(bytes))
                    ? new FaceObservation(Landmarks(), 80, 90, 160, 200, W, H)
                    : null);
            // Kimlik fotoğrafı "victim" vektörü; kareler etiketlerine göre.
            mock.Setup(b => b.ComputeEmbedding(It.IsAny<byte[]>())).Returns(Vector("victim"));
            mock.Setup(b => b.ComputeEmbedding(It.IsAny<byte[]>(), It.IsAny<float[]>()))
                .Returns((byte[] bytes, float[] _) =>
                    Vector(_frames.TryGetValue(Convert.ToBase64String(bytes), out var who) ? who : "none"));
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

    private static Choreography Demand(params LivenessEvent[] events) => new()
    {
        Version = ChoreographyGenerator.Version,
        Events = events.ToList(),
    };

    /// <summary>Kırpma · çift kırpma · ağız açma — dört olay karesi, üç nötr kare.</summary>
    private static readonly Choreography Typical =
        Demand(LivenessEvent.Blink, LivenessEvent.DoubleBlink, LivenessEvent.MouthOpen);

    /// <summary>Diziyi sahneden kurar: her adımda bir nötr kare, istenen sayıda olay karesi.</summary>
    private static ChoreographyProof Perform(Scene scene, Choreography demanded,
        Func<int, string>? neutralWho = null, Func<int, string>? eventWho = null)
    {
        var proof = new ChoreographyProof
        {
            Version = ChoreographyGenerator.Version, ElapsedMs = 11000, Resets = 0, WrongEvents = 0,
        };
        for (int i = 0; i < demanded.Events.Count; i++)
        {
            var step = new ChoreographyProofStep { Neutral = { scene.Add(neutralWho?.Invoke(i) ?? "victim") } };
            for (int e = 0; e < ChoreographyGenerator.FramesFor(demanded.Events[i]); e++)
                step.Event.Add(scene.Add(eventWho?.Invoke(i) ?? "victim"));
            proof.Steps.Add(step);
        }
        return proof;
    }

    // ── Yapı ─────────────────────────────────────────────────────────────────

    [Fact]
    public void YapiKurallari()
    {
        var scene = new Scene();
        Assert.Null(ChoreographyVerifier.ValidateStructure(Perform(scene, Typical), Typical));

        var badVersion = Perform(scene, Typical); badVersion.Version = 1;
        Assert.Equal("version", ChoreographyVerifier.ValidateStructure(badVersion, Typical));

        var missingStep = Perform(scene, Typical); missingStep.Steps.RemoveAt(2);
        Assert.Equal("steps", ChoreographyVerifier.ValidateStructure(missingStep, Typical));

        var noNeutral = Perform(scene, Typical); noNeutral.Steps[1].Neutral.Clear();
        Assert.Equal("neutral", ChoreographyVerifier.ValidateStructure(noNeutral, Typical));

        var twoNeutral = Perform(scene, Typical); twoNeutral.Steps[0].Neutral.Add(scene.Add());
        Assert.Equal("neutral", ChoreographyVerifier.ValidateStructure(twoNeutral, Typical));

        var missingEvent = Perform(scene, Typical); missingEvent.Steps[2].Event.Clear();
        Assert.Equal("event", ChoreographyVerifier.ValidateStructure(missingEvent, Typical));

        // Tek kırpmada ikinci olay karesi de bozuk yapı: ölçülmeyen, yükü büyüten kare.
        var extraEvent = Perform(scene, Typical); extraEvent.Steps[0].Event.Add(scene.Add());
        Assert.Equal("event", ChoreographyVerifier.ValidateStructure(extraEvent, Typical));

        // Çift kırpma iki olay karesi ister.
        var halfDouble = Perform(scene, Typical); halfDouble.Steps[1].Event.RemoveAt(1);
        Assert.Equal("event", ChoreographyVerifier.ValidateStructure(halfDouble, Typical));
    }

    /// <summary>Eski duruş kanıtı (sürüm 1) yeni diziye göre ölçülmez — yapı bozuk.</summary>
    [Fact]
    public void EskiSurumKanitReddedilir()
    {
        var scene = new Scene();
        var old = Perform(scene, Typical); old.Version = 1;

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(old, Typical, new byte[] { 1 });
        Assert.Equal(ChoreographyVerifier.StatusInvalid, o.Status);
        Assert.Equal("version", o.InvalidReason);
    }

    [Fact]
    public void CozulemeyenKareYapiyiBozar()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical);
        proof.Steps[1].Event[1] = "bu-base64-degil!";

        var o = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(ChoreographyVerifier.StatusInvalid, o.Status);
        Assert.Equal("frame", o.InvalidReason);
    }

    // ── Meşru akış ───────────────────────────────────────────────────────────

    [Fact]
    public void MesruAkisOlculurVeKimlikTutar()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical);

        var c = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });

        Assert.Equal(ChoreographyVerifier.StatusMeasured, c.Status);
        Assert.Equal("blink,double_blink,mouth_open", c.Demanded);

        // Kimlik: üç nötr kare + dört olay karesi.
        Assert.Equal(3, c.Identity!.Count);
        Assert.Equal(4, c.EventIdentity!.Count);
        Assert.Equal(1.0, c.IdentityMin!.Value, 3);

        Assert.Equal(7, c.Frames);
        Assert.Equal(7, c.Faces);

        // Olay ölçümü her olay karesi için bir satır, adım numarasıyla.
        Assert.Equal(4, c.Events!.Count);
        Assert.Equal(new[] { 0, 1, 1, 2 }, c.Events.Select(e => e.Step).ToArray());
        Assert.Equal("double_blink", c.Events[1].Type);
    }

    // ── Saldırılar ───────────────────────────────────────────────────────────

    /// <summary>
    /// 🔴 KAYNAK AYRIMI: nötr karelerde kart sahibinin fotoğrafı, hareketi saldırgan yapıyor.
    /// Olay karelerinde kimlik tutmaz → kapının baktığı en küçük değer düşer.
    /// </summary>
    [Fact]
    public void HareketiBaskasiYaparsaYakalanir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, eventWho: i => i == 2 ? "attacker" : "victim");

        var c = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(ChoreographyVerifier.StatusMeasured, c.Status);
        Assert.All(c.Identity!, v => Assert.Equal(1.0, v, 3));
        Assert.Equal(0.0, c.IdentityMin!.Value, 3);
    }

    /// <summary>Ters düzen: hareketler kart sahibinin, aradaki kare başkasının — yine yakalanır.</summary>
    [Fact]
    public void AradakiKareBaskasininsaYakalanir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical, neutralWho: i => i == 1 ? "attacker" : "victim");

        var c = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(0.0, c.IdentityMin!.Value, 3);
    }

    /// <summary>Yüz bulunamayan kare 0 sayılır: "yüz yok" karesiyle kimlik kapısı atlatılamaz.</summary>
    [Fact]
    public void YuzsuzKareKimlikteSifirSayilir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical);
        var models = scene.Models();
        var faceless = proof.Steps[0].Event[0];
        models.Setup(b => b.DetectFace(It.Is<byte[]>(x => Convert.ToBase64String(x) == faceless)))
              .Returns((FaceObservation?)null);

        var c = new ChoreographyVerifier(models.Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(0.0, c.IdentityMin!.Value, 3);
        Assert.Equal(6, c.Faces);
    }

    [Fact]
    public void KimlikFotografiYoksaKimlikOlculmez()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical);

        var c = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, idPhotoBytes: null);
        Assert.Null(c.Identity);
        Assert.Null(c.EventIdentity);
        Assert.Null(c.IdentityMin);
    }

    /// <summary>
    /// İstemcinin iz kaydı ölçüm satırına taşınır — ama istemci metni: sınırlı ve ayıklanmış.
    /// </summary>
    [Fact]
    public void IzKaydiTasinirVeAyiklanir()
    {
        var scene = new Scene();
        var proof = Perform(scene, Typical);
        proof.Trace = "0.0 start;1.2 e0 ev blink;" + (char)1 + "bozuk" + (char)10;
        proof.TrackingChanges = 2;

        var c = new ChoreographyVerifier(scene.Models().Object).Measure(proof, Typical, new byte[] { 1 });
        Assert.Equal(2, c.TrackingChanges);
        Assert.StartsWith("0.0 start;1.2 e0 ev blink;", c.Trace);
        Assert.DoesNotContain((char)10, c.Trace!);
        Assert.DoesNotContain((char)1, c.Trace!);

        var huge = ChoreographyVerifier.SanitizeTrace(new string('a', 10_000));
        Assert.Equal(ChoreographyVerifier.MaxTraceChars, huge!.Length);
        Assert.Null(ChoreographyVerifier.SanitizeTrace(null));
    }
}
