using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Canlı benzerlik akışı — aday değerlendirme (K4/K5/K6) ve akış önbelleği.
///
/// Bu testlerin koruduğu asıl şey KARARLAR: adayların sırası, her adayın KENDİ kırpmasıyla
/// değerlendirilmesi, register'ın önbelleğe bakmaması ve reddedilen adayların da ölçülmesi.
/// </summary>
public class StreamingSimilarityTests
{
    private readonly Mock<IEnclaveKeyService> _enclaveKeys = new();
    private readonly Mock<IKmsService> _kms = new();
    private readonly Mock<IBiometricService> _biometrics = new();
    private readonly Mock<ITicketMacService> _ticketMac = new();
    private readonly Mock<IAntiSpoofService> _antiSpoof = new();
    private readonly FlowEmbeddingCache _cache = new();
    private readonly EnclaveService _service;

    public StreamingSimilarityTests()
    {
        _antiSpoof.Setup(a => a.IsModelLoaded).Returns(true);
        _antiSpoof.Setup(a => a.Predict(It.IsAny<byte[]>())).Returns(new[] { 0f, 1.0f, 0f });
        _biometrics.Setup(b => b.IsModelLoaded).Returns(true);

        _service = new EnclaveService(
            _enclaveKeys.Object, _kms.Object, _biometrics.Object,
            _ticketMac.Object, _antiSpoof.Object, _cache);
    }

    private static string B64(string s) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s));

    /// <summary>
    /// Dg2FaceExtractor gerçek bir JPEG SOI..EOI dizisi arar (mock edilemez, statik sınıf).
    /// Bu yüzden testlerde asgari geçerli bir çerçeve kullanılır — içeriği önemsiz, çünkü
    /// gömme hesabı zaten mock'lanmış IBiometricService üzerinden gidiyor.
    /// </summary>
    private static string FakeDg2() =>
        Convert.ToBase64String([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9]);

    private static SecurePayload PayloadWith(params RegistrationCandidate[] candidates) =>
        new()
        {
            DG2 = FakeDg2(),
            UserSelfie = B64("legacy-selfie"),
            AntiSpoofCrop = B64("legacy-crop"),
            Candidates = candidates.Length > 0 ? [.. candidates] : null,
        };

    // ── Aday listesi kurulumu ────────────────────────────────────────────────

    [Fact]
    public void BuildCandidateList_NoCandidates_FallsBackToLegacySinglePhoto()
    {
        // Streaming göndermeyen eski istemci: davranış birebir aynı kalmalı.
        var list = EnclaveService.BuildCandidateList(PayloadWith());

        Assert.Single(list);
        Assert.Equal(1, list[0].Rank);
        Assert.Equal(B64("legacy-selfie"), list[0].UserSelfie);
        Assert.Equal(B64("legacy-crop"), list[0].AntiSpoofCrop);
    }

    [Fact]
    public void BuildCandidateList_OrdersByRank_ClientBestFirst()
    {
        // K5: önce istemcinin en iyi seçtiği kare, sonra ikincisi — gövde sırası ne olursa olsun.
        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 2, UserSelfie = B64("s2"), AntiSpoofCrop = B64("c2") },
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("c1") });

        var list = EnclaveService.BuildCandidateList(payload);

        Assert.Equal(2, list.Count);
        Assert.Equal(1, list[0].Rank);
        Assert.Equal(2, list[1].Rank);
    }

    [Fact]
    public void BuildCandidateList_CapsAtTwoCandidates()
    {
        // Her aday iki ONNX çıkarımı demek: sınırsız aday register'ı ucuz bir CPU tüketim
        // yüzeyine çevirirdi.
        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1") },
            new RegistrationCandidate { Rank = 2, UserSelfie = B64("s2") },
            new RegistrationCandidate { Rank = 3, UserSelfie = B64("s3") },
            new RegistrationCandidate { Rank = 4, UserSelfie = B64("s4") });

        Assert.Equal(2, EnclaveService.BuildCandidateList(payload).Count);
    }

    [Fact]
    public void BuildCandidateList_SkipsEmptySelfies()
    {
        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = "" },
            new RegistrationCandidate { Rank = 2, UserSelfie = B64("s2") });

        var list = EnclaveService.BuildCandidateList(payload);

        Assert.Single(list);
        Assert.Equal(2, list[0].Rank);
    }

    // ── Aday değerlendirme: sıra, tam kapı, ölçüm ────────────────────────────

    [Fact]
    public void EvaluateCandidates_FirstCandidatePasses_SecondNotEvaluated()
    {
        // K5 gerekçesi veri kalitesi: 1. aday geçiyorsa sınırdaki kareyi değerlendirmeyiz.
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.80f);

        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("c1") },
            new RegistrationCandidate { Rank = 2, UserSelfie = B64("s2"), AntiSpoofCrop = B64("c2") });

        var (score, outcomes) = _service.EvaluateCandidates(payload, new DiagLog());

        Assert.Equal(0.80f, score, 3);
        Assert.Single(outcomes);
        Assert.Equal(1, outcomes[0].Rank);
        Assert.Equal(FrameOutcomes.Pass, outcomes[0].Outcome);
    }

    [Fact]
    public void EvaluateCandidates_FirstFailsSecondPasses_BothRecorded()
    {
        // ⚠️ İşin ASIL amacı: 1. aday düşüp 2. aday geçtiğinde İKİSİ DE görünmeli. Cihazın
        // "en iyi" hükmü ile enclave'in hükmü arasındaki sapmanın etiketli örneği budur.
        var selfie1 = Convert.FromBase64String(B64("s1"));
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.Is<byte[]>(p => p.SequenceEqual(selfie1))))
            .Throws(new BiometricMismatchException(0.11f, "eşleşmedi"));
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.Is<byte[]>(p => !p.SequenceEqual(selfie1))))
            .Returns(0.44f);

        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("c1") },
            new RegistrationCandidate { Rank = 2, UserSelfie = B64("s2"), AntiSpoofCrop = B64("c2") });

        var (score, outcomes) = _service.EvaluateCandidates(payload, new DiagLog());

        Assert.Equal(0.44f, score, 3);
        Assert.Equal(2, outcomes.Count);
        Assert.Equal(FrameOutcomes.FailSimilarity, outcomes[0].Outcome);
        Assert.Equal(0.11, outcomes[0].MatchScore, 3);
        Assert.Equal(FrameOutcomes.Pass, outcomes[1].Outcome);
    }

    [Fact]
    public void EvaluateCandidates_EachCandidateUsesItsOwnCrop()
    {
        // K6: benzerlik bir adaydan, canlılık başka adaydan ALINAMAZ. Karıştırmak gerçek bir
        // açıktır — saldırgan gerçek yüzü benzerliğe, canlı kırpmayı anti-spoof'a verirdi.
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.50f);

        var seenCrops = new List<byte[]>();
        _antiSpoof.Setup(a => a.Predict(It.IsAny<byte[]>()))
            .Callback<byte[]>(seenCrops.Add)
            .Returns(new[] { 0f, 1.0f, 0f });

        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("crop-1") });

        _service.EvaluateCandidates(payload, new DiagLog());

        Assert.Single(seenCrops);
        Assert.Equal(Convert.FromBase64String(B64("crop-1")), seenCrops[0]);
    }

    [Fact]
    public void EvaluateCandidates_LivenessFailsForBoth_ThrowsAndCarriesBothOutcomes()
    {
        // Kontrol KALDIRILMADI (K3): canlılık düşen aday geçemez ve hiçbiri geçmezse akış reddedilir.
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>())).Returns(0.60f);
        _antiSpoof.Setup(a => a.Predict(It.IsAny<byte[]>())).Returns(new[] { 0.9f, 0.05f, 0.05f });

        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("c1") },
            new RegistrationCandidate { Rank = 2, UserSelfie = B64("s2"), AntiSpoofCrop = B64("c2") });

        var ex = Assert.Throws<RegistrationException>(() => _service.EvaluateCandidates(payload, new DiagLog()));

        Assert.Equal("ERR_ANTISPOOFING", ex.ErrorCode);
        // Reddedilen adayların ölçüsü istisnayla TAŞINIR — yalnız geçeni loglamak dağılımı yok ederdi.
        Assert.NotNull(ex.CandidateOutcomes);
        Assert.Equal(2, ex.CandidateOutcomes!.Count);
        Assert.All(ex.CandidateOutcomes, o => Assert.Equal(FrameOutcomes.FailLiveness, o.Outcome));
        // P(live) kırılımı da taşınır: %46,2 anomalisi yalnız buradan görülebilir.
        Assert.Equal(0.05, ex.CandidateOutcomes[0].PLive, 3);
        Assert.Equal(0.9, ex.CandidateOutcomes[0].C0, 3);
    }

    [Fact]
    public void EvaluateCandidates_SimilarityBelowThreshold_IsRejected()
    {
        // Eşik DEĞİŞMEDİ: bu iş ölçüm topluyor, karar vermiyor.
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Throws(new BiometricMismatchException(EnclaveService.BiometricThreshold - 0.01f, "eşik altı"));

        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("c1") });

        var ex = Assert.Throws<RegistrationException>(() => _service.EvaluateCandidates(payload, new DiagLog()));

        Assert.Equal("ERR_BIOMETRIC_MISMATCH", ex.ErrorCode);
        Assert.Single(ex.CandidateOutcomes!);
        Assert.Equal(FrameOutcomes.FailSimilarity, ex.CandidateOutcomes![0].Outcome);
    }

    [Fact]
    public void EvaluateCandidates_DoesNotConsultStreamingCache()
    {
        // K4: register durumsuzdur. Önbellekte bu akış için "onaylanmış" bir gömme olsa BİLE
        // register onu görmez ve kendi kapısını uygular.
        _cache.Store(Guid.NewGuid().ToString(), new float[512]);
        _biometrics.Setup(b => b.VerifyFaceParallel(It.IsAny<byte[]>(), It.IsAny<byte[]>()))
            .Throws(new BiometricMismatchException(0.05f, "eşleşmedi"));

        var payload = PayloadWith(
            new RegistrationCandidate { Rank = 1, UserSelfie = B64("s1"), AntiSpoofCrop = B64("c1") });

        Assert.Throws<RegistrationException>(() => _service.EvaluateCandidates(payload, new DiagLog()));
        // Gömme önbelleği hiç okunmadı: karar yalnız yükten hesaplandı.
        _biometrics.Verify(b => b.ComputeEmbedding(It.IsAny<byte[]>()), Times.Never);
    }

    // ── Akış önbelleği ───────────────────────────────────────────────────────

    [Fact]
    public void FlowEmbeddingCache_StoreAndGet_RoundTrips()
    {
        var cache = new FlowEmbeddingCache();
        var flowId = Guid.NewGuid().ToString();
        var embedding = new float[] { 0.1f, 0.2f, 0.3f };

        cache.Store(flowId, embedding);

        Assert.Equal(embedding, cache.Get(flowId));
    }

    [Fact]
    public void FlowEmbeddingCache_Remove_DropsEntry()
    {
        // Akış bitince gömme RAM'den hemen silinir — TTL beklenmez.
        var cache = new FlowEmbeddingCache();
        var flowId = Guid.NewGuid().ToString();
        cache.Store(flowId, new float[] { 1f });

        cache.Remove(flowId);

        Assert.Null(cache.Get(flowId));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void FlowEmbeddingCache_AfterTtl_EntryIsGone()
    {
        // KABUL ÖLÇÜTÜ: gömme vektörü TTL sonunda RAM'den silinir. Saat enjekte edilmeseydi
        // bu ancak 15 dakika bekleyen bir testle sınanabilirdi, yani hiç sınanmazdı.
        var clock = DateTimeOffset.UtcNow;
        var cache = new FlowEmbeddingCache(() => clock);
        var flowId = Guid.NewGuid().ToString();
        cache.Store(flowId, new float[] { 1f });

        Assert.NotNull(cache.Get(flowId));

        clock = clock.Add(FlowEmbeddingCache.Ttl).AddSeconds(1);

        Assert.Null(cache.Get(flowId));
    }

    [Fact]
    public void FlowEmbeddingCache_ExpiredEntriesArePrunedOnWrite()
    {
        // Ayrı bir zamanlayıcı YOK: temizlik yazma yolunda yapılır. Bu olmasa süresi dolan
        // girdiler, kimse onları OKUMADIĞI sürece RAM'de sonsuza dek kalırdı.
        var clock = DateTimeOffset.UtcNow;
        var cache = new FlowEmbeddingCache(() => clock);
        cache.Store(Guid.NewGuid().ToString(), new float[] { 1f });
        cache.Store(Guid.NewGuid().ToString(), new float[] { 2f });
        Assert.Equal(2, cache.Count);

        clock = clock.Add(FlowEmbeddingCache.Ttl).AddSeconds(1);
        cache.Store(Guid.NewGuid().ToString(), new float[] { 3f });

        // Eski iki girdi toplandı, yalnız yeni olan kaldı.
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void FlowEmbeddingCache_UnknownFlow_ReturnsNull()
    {
        Assert.Null(new FlowEmbeddingCache().Get(Guid.NewGuid().ToString()));
    }

    [Fact]
    public void StreamingCheck_WithoutPrepare_Throws()
    {
        // Prepare yapılmamış (ya da TTL dolmuş) akış hiçbir şey ölçmeden reddedilir —
        // uydurma akış numarasıyla eşleşme kâhini çalıştırılamaz.
        var request = new StreamingCheckRequest
        {
            FlowId = Guid.NewGuid().ToString(),
            EncryptedKey = "enc",
            AesBlob = "blob",
        };

        Assert.Throws<InvalidOperationException>(() => _service.StreamingCheck(request, new DiagLog()));
    }

    [Fact]
    public void StreamingCheck_InvalidFlowId_Throws()
    {
        var request = new StreamingCheckRequest { FlowId = "not-a-guid", EncryptedKey = "e", AesBlob = "b" };

        Assert.Throws<InvalidOperationException>(() => _service.StreamingCheck(request, new DiagLog()));
    }

    // ── Eşik paylaşımı ───────────────────────────────────────────────────────

    [Fact]
    public void BiometricThreshold_IsSharedBetweenStreamingAndRegister()
    {
        // Streaming "geçti" deyip register'ın aynı kareyi reddetmesi, kullanıcıyı açıklanamaz
        // bir duvara çarptırırdı. Sabit tek kaynaktan gelir ve 0.20'dir (bu iş eşiği DEĞİŞTİRMEZ).
        Assert.Equal(0.20f, EnclaveService.BiometricThreshold, 4);
    }
}
