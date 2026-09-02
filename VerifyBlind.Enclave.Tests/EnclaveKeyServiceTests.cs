using VerifyBlind.Core.Crypto;
using VerifyBlind.Enclave.Services;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class EnclaveKeyServiceTests
{
    private readonly Mock<INsmProvider> _nsm = new();
    private readonly EnclaveKeyService _service;

    public EnclaveKeyServiceTests()
    {
        // Setup NSM to return fake attestation bytes
        _nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
            .Returns(new byte[] { 0x01, 0x02, 0x03, 0x04 });

        _service = new EnclaveKeyService(_nsm.Object, new RelayClock());
    }


    // ── Relay saati düzeltmesi ────────────────────────────────────────────────
    //
    // 2026-08-25 üretim olayı: enclave'in saati geri kaldı, kendi saatiyle "vadem dolmadı" deyip
    // attestation belgesini hiç yenilemedi ve süresi DOLMUŞ bir AWS sertifikası servis etti.
    // Kullanıcılar uygulamayı açamadı; sunucu 24 saat boyunca fark etmedi. Düzeltme: kararı
    // max(enclave saati, relay saati) ile ver.

    [Fact]
    public void RelayClock_ReportedTimeInPast_DoesNotMoveClockBackwards()
    {
        var clock = new RelayClock();
        var before = DateTime.UtcNow;
        clock.Report(DateTimeOffset.UtcNow.AddHours(-5));   // relay geride/yalan söylüyor

        // Saat GERİ gitmemeli: aksi halde bu sınıf bir saldırı yüzeyi olurdu (bayat belgeyi
        // taze göstermek). max() yalnız ileri taşır.
        Assert.True(clock.EffectiveUtcNow >= before);
    }

    /// REGRESYON: kayma, BİLDİRİM ANINDA ölçülmeli. "Son bildirilen saat - şu anki saat" diye
    /// hesaplanırsa ölçüm, kaymayı değil son bildirimden bu yana geçen süreyi gösterir. İlk canlı
    /// okumada (2026-08-25) enclave senkronken ölçüm "39 saniye ileri" diyordu, çünkü relay 39
    /// saniye önce bildirmişti — alarmı bunun üstüne kurmak onu işe yaramaz yapardı.
    [Fact]
    public void RelayClock_DriftIsMeasuredAtReportTime_NotAffectedByElapsedTime()
    {
        var clock = new RelayClock();
        clock.Report(DateTimeOffset.UtcNow);   // senkron: kayma ~0

        Thread.Sleep(150);                     // zaman geçsin

        var drift = clock.DriftBehindRelay;
        Assert.NotNull(drift);
        // Geçen süre kaymaya KARIŞMAMALI. Eski hesapla bu değer ~-150 ms olurdu.
        Assert.True(Math.Abs(drift!.Value.TotalMilliseconds) < 50,
                    $"kayma geçen süreden etkilenmiş: {drift.Value.TotalMilliseconds} ms");
    }

    [Fact]
    public void RelayClock_ReportedTimeAhead_MovesClockForward()
    {
        var clock = new RelayClock();
        var ahead = DateTimeOffset.UtcNow.AddHours(3);
        clock.Report(ahead);

        Assert.True(clock.EffectiveUtcNow >= ahead.UtcDateTime.AddSeconds(-1));
    }

    [Fact]
    public void GetAttestationDocument_RelayClockPastRefreshTime_MintsAgain()
    {
        var nsm = new Mock<INsmProvider>();
        nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
            .Returns(new byte[] { 0xA0 });   // mock belge → yedek TTL yolu
        var clock = new RelayClock();
        var svc = new EnclaveKeyService(nsm.Object, clock);

        svc.GetAttestationDocument();   // ilk mint
        nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()),
                   Times.Once);

        // Enclave'in KENDİ saatine göre vade dolmadı; relay ise çok ilerideyiz diyor.
        clock.Report(DateTimeOffset.UtcNow.AddHours(4));
        svc.GetAttestationDocument();

        nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()),
                   Times.Exactly(2));
    }

    [Fact]
    public void GetAttestationDocument_RelayDrivenRefresh_IsRateLimited()
    {
        var nsm = new Mock<INsmProvider>();
        nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
            .Returns(new byte[] { 0xA0 });
        var clock = new RelayClock();
        var svc = new EnclaveKeyService(nsm.Object, clock);

        svc.GetAttestationDocument();
        clock.Report(DateTimeOffset.UtcNow.AddHours(4));
        svc.GetAttestationDocument();   // relay tetikli yenileme (2. mint)
        svc.GetAttestationDocument();   // hemen ardından: hız sınırı devrede
        svc.GetAttestationDocument();

        // Yalan/bozuk bir relay saati her isteği NSM çağrısına çeviremez.
        nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()),
                   Times.Exactly(2));
    }

    // ── Key Material ──────────────────────────────────────────────────────────

    [Fact]
    public void GetEnclavePublicKey_ReturnsNonEmpty()
    {
        var pubKey = _service.GetEnclavePublicKey();
        Assert.NotEmpty(pubKey);
    }

    [Fact]
    public void GetEnclavePublicKey_IsValidBase64()
    {
        var pubKey = _service.GetEnclavePublicKey();
        var bytes = Convert.FromBase64String(pubKey);
        Assert.True(bytes.Length > 0);
    }

    // ── Sign & Verify ─────────────────────────────────────────────────────────

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        const string data = "test-data-12345";
        var signature = _service.SignDataWithEnclaveKey(data);
        var isValid = _service.VerifyEnclaveSignature(data, signature);

        Assert.NotEmpty(signature);
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyEnclaveSignature_TamperedData_Fails()
    {
        const string data = "original-data";
        var signature = _service.SignDataWithEnclaveKey(data);

        var isValid = _service.VerifyEnclaveSignature("tampered-data", signature);
        Assert.False(isValid);
    }

    [Fact]
    public void Sign_DifferentData_ProducesDifferentSignatures()
    {
        var sig1 = _service.SignDataWithEnclaveKey("data-one");
        var sig2 = _service.SignDataWithEnclaveKey("data-two");

        Assert.NotEqual(sig1, sig2);
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    [Fact]
    public void DecryptWithEnclaveKey_AfterRsaEncrypt_RoundTrips()
    {
        var pubKey = _service.GetEnclavePublicKey();
        var cipherText = CryptoUtils.RsaEncrypt("hello-enclave", pubKey);

        var decrypted = _service.DecryptWithEnclaveKey(cipherText);
        Assert.Equal("hello-enclave", decrypted);
    }

    // ── Attestation zinciri: tazeleme kararı ZİNCİRİN minimumundan verilir ────
    //
    // 2026-08-31: relay taze bir leaf (notAfter 19:55:14) taşıyan belgeyi 200 ile geçirdi, iPhone
    // aynı belgeyi "AWS CA zinciri BAŞARISIZ: … certificate is expired" ile reddetti. Nitro
    // zincirinde ömürler eşit değil — leaf 3 saat, instance CA 24 saat, zonal ~6 gün — ve burası
    // tazeleme anını YALNIZ leaf'e bakarak seçtiği için ara sertifikası ölmek üzere olan bir belgeyi
    // saatlerce cache'leyebiliyordu: leaf taze, zincir ölü.

    /// COSE_Sign1 = [protected, unprotected, payload, signature];
    /// payload = { "certificate": leafDER, "cabundle": [DER, …] } — NSM'in gerçek çıktısının
    /// bu kod yolunun okuduğu kısmı.
    private static byte[] BuildAttestationDoc(X509Certificate2 leaf, params X509Certificate2[] cabundle)
    {
        var payload = new CborWriter();
        payload.WriteStartMap(2);
        payload.WriteTextString("certificate");
        payload.WriteByteString(leaf.RawData);
        payload.WriteTextString("cabundle");
        payload.WriteStartArray(cabundle.Length);
        foreach (var cert in cabundle) payload.WriteByteString(cert.RawData);
        payload.WriteEndArray();
        payload.WriteEndMap();

        var cose = new CborWriter();
        cose.WriteStartArray(4);
        cose.WriteByteString([]);
        cose.WriteStartMap(0);
        cose.WriteEndMap();
        cose.WriteByteString(payload.Encode());
        cose.WriteByteString([]);
        cose.WriteEndArray();
        return cose.Encode();
    }

    private static X509Certificate2 MakeCert(string cn, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(notBefore, notAfter);
    }

    private static EnclaveKeyService ServiceReturning(byte[] doc)
    {
        var nsm = new Mock<INsmProvider>();
        nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
            .Returns(doc);
        return new EnclaveKeyService(nsm.Object, new RelayClock());
    }

    [Fact]
    public void GetAttestationDocument_CabundleExpiresBeforeLeaf_SchedulesRefreshFromChainMinimum()
    {
        var now = DateTimeOffset.UtcNow;
        using var leaf = MakeCert("i-abc-enc123.eu-central-1.aws", now.AddHours(-1), now.AddHours(3));
        using var instanceCa = MakeCert("i-abc.eu-central-1.aws.nitro-enclaves", now.AddHours(-22), now.AddHours(2));
        using var root = MakeCert("aws.nitro-enclaves", now.AddYears(-5), now.AddYears(20));

        var svc = ServiceReturning(BuildAttestationDoc(leaf, root, instanceCa));
        svc.GetAttestationDocument();

        // Leaf'e göre değil, ölmeye EN YAKIN halkaya göre tazelenmeli.
        Assert.Equal(instanceCa.NotAfter.ToUniversalTime(), svc.AttestationNotAfter!.Value.UtcDateTime);
        Assert.Equal(instanceCa.NotAfter.ToUniversalTime().AddMinutes(-60), svc.AttestationRefreshAt);
    }

    [Fact]
    public void GetAttestationDocument_LeafExpiresFirst_SchedulesRefreshFromLeaf()
    {
        var now = DateTimeOffset.UtcNow;
        using var leaf = MakeCert("i-abc-enc123.eu-central-1.aws", now.AddHours(-1), now.AddHours(2));
        using var instanceCa = MakeCert("i-abc.eu-central-1.aws.nitro-enclaves", now.AddHours(-1), now.AddHours(23));

        var svc = ServiceReturning(BuildAttestationDoc(leaf, instanceCa));
        svc.GetAttestationDocument();

        Assert.Equal(leaf.NotAfter.ToUniversalTime(), svc.AttestationNotAfter!.Value.UtcDateTime);
        Assert.Equal(leaf.NotAfter.ToUniversalTime().AddMinutes(-60), svc.AttestationRefreshAt);
    }

    [Fact]
    public void GetAttestationDocument_UnparsableCabundleEntry_FallsBackToFixedTtl()
    {
        // Zinciri okuyamadığımızda sabit yedek TTL'ye düşülür (mock/dev belgesiyle aynı yol) —
        // burada asıl mesele, bir halkanın çözülememesinin leaf'in tarihine körü körüne
        // güvenmeye DÖNMEMESİ.
        var now = DateTimeOffset.UtcNow;
        using var leaf = MakeCert("i-abc-enc123.eu-central-1.aws", now.AddHours(-1), now.AddHours(3));

        var payload = new CborWriter();
        payload.WriteStartMap(2);
        payload.WriteTextString("certificate");
        payload.WriteByteString(leaf.RawData);
        payload.WriteTextString("cabundle");
        payload.WriteStartArray(1);
        payload.WriteByteString([0x01, 0x02, 0x03]);   // sertifika değil
        payload.WriteEndArray();
        payload.WriteEndMap();

        var cose = new CborWriter();
        cose.WriteStartArray(4);
        cose.WriteByteString([]);
        cose.WriteStartMap(0);
        cose.WriteEndMap();
        cose.WriteByteString(payload.Encode());
        cose.WriteByteString([]);
        cose.WriteEndArray();

        var svc = ServiceReturning(cose.Encode());
        svc.GetAttestationDocument();

        Assert.Null(svc.AttestationNotAfter);
        Assert.NotEqual(leaf.NotAfter.ToUniversalTime().AddMinutes(-60), svc.AttestationRefreshAt);
    }

    // ── Attestation ───────────────────────────────────────────────────────────

    [Fact]
    public void GetAttestationDocument_CallsNsmProvider()
    {
        var attestation = _service.GetAttestationDocument();

        _nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()), Times.Once);
        Assert.NotEmpty(attestation);
    }

    [Fact]
    public void GetAttestationDocument_IsCachedOnSecondCall()
    {
        var first = _service.GetAttestationDocument();
        var second = _service.GetAttestationDocument();

        // NSM should only be called once (cached after first call)
        _nsm.Verify(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()), Times.Once);
        Assert.Equal(first, second);
    }

    [Fact]
    public void GetAttestationDocument_PassesEnclavePublicKeyAsUserData()
    {
        // The attestation must be bound to the enclave's public key — the key bytes are
        // submitted to the NSM as user_data so a verifier can trust the key came from this enclave.
        var expectedUserData = Encoding.UTF8.GetBytes(_service.GetEnclavePublicKey());

        _service.GetAttestationDocument();

        _nsm.Verify(n => n.GetAttestationDocument(
            It.Is<byte[]>(b => b.SequenceEqual(expectedUserData)),
            It.IsAny<byte[]?>(),
            It.IsAny<byte[]?>()), Times.Once);
    }

    // ── Error Paths ───────────────────────────────────────────────────────────

    [Fact]
    public void VerifyEnclaveSignature_GarbageSignature_ReturnsFalseNeverThrows()
    {
        // VerifyEnclaveSignature delegates to CryptoUtils.VerifySignature, which must
        // never throw — malformed input is a "false", not a crash.
        Assert.False(_service.VerifyEnclaveSignature("data", "not-base64!!!"));
    }

    [Fact]
    public void VerifyEnclaveSignature_SignatureFromForeignKey_ReturnsFalse()
    {
        var (foreignPriv, _) = CryptoUtils.GenerateRsaKeyPair();
        var foreignSig = CryptoUtils.SignData("data", foreignPriv);

        Assert.False(_service.VerifyEnclaveSignature("data", foreignSig));
    }

    [Fact]
    public void DecryptWithEnclaveKey_GarbageCipherText_Throws()
        => Assert.ThrowsAny<Exception>(() => _service.DecryptWithEnclaveKey("not-base64!!!"));

    [Fact]
    public void DecryptWithEnclaveKey_CipherForDifferentKey_Throws()
    {
        var (_, foreignPub) = CryptoUtils.GenerateRsaKeyPair();
        var cipher = CryptoUtils.RsaEncrypt("secret", foreignPub);

        // Encrypted to someone else's key — this enclave must not be able to decrypt it.
        Assert.ThrowsAny<CryptographicException>(() => _service.DecryptWithEnclaveKey(cipher));
    }

    // ── Signature Properties ──────────────────────────────────────────────────

    [Fact]
    public void SignDataWithEnclaveKey_SameDataTwice_ProducesDifferentSignatures()
    {
        // RSA-PSS uses a random salt — identical input must not produce identical signatures.
        Assert.NotEqual(_service.SignDataWithEnclaveKey("x"), _service.SignDataWithEnclaveKey("x"));
    }

    [Fact]
    public void EmptyData_SignAndVerify_RoundTrips()
    {
        var sig = _service.SignDataWithEnclaveKey("");
        Assert.True(_service.VerifyEnclaveSignature("", sig));
    }

    // ── Per-Instance Key Material ─────────────────────────────────────────────

    [Fact]
    public void DecryptWithEnclaveKey_DynamicKey_RoundTrips()
    {
        var nsm = new Mock<INsmProvider>();
        var svc = new EnclaveKeyService(nsm.Object, new RelayClock());

        var cipher = CryptoUtils.RsaEncrypt("dynamic-secret", svc.GetEnclavePublicKey());
        Assert.Equal("dynamic-secret", svc.DecryptWithEnclaveKey(cipher));
    }

    // ── Program.cs DI Behaviour ───────────────────────────────────────────────
    // Program.cs registers IEnclaveKeyService → EnclaveKeyService. The constructor
    // generates a fresh RSA-2048 key pair every time the service is built, so the
    // hardcoded dev keys from the public repo are no longer in play. These tests
    // pin that new reality.

    [Fact]
    public void DiContainer_MirroringProgramCs_GeneratesFreshKeyPair()
    {
        // Arrange: replicate Program.cs's IEnclaveKeyService registration.
        var services = new ServiceCollection();
        services.AddSingleton<INsmProvider>(_ =>
        {
            var nsm = new Mock<INsmProvider>();
            nsm.Setup(n => n.GetAttestationDocument(It.IsAny<byte[]>(), It.IsAny<byte[]?>(), It.IsAny<byte[]?>()))
                .Returns(new byte[] { 0x00 });
            return nsm.Object;
        });
        services.AddSingleton<RelayClock>();   // Program.cs ile aynı: enclave saatine relay düzeltmesi
        services.AddSingleton<IEnclaveKeyService, EnclaveKeyService>();

        using var sp = services.BuildServiceProvider();
        var diInstance = sp.GetRequiredService<IEnclaveKeyService>();

        // A separately-constructed instance must produce a DIFFERENT public key —
        // proving no static/hardcoded material is in use.
        var standalone = new EnclaveKeyService(Mock.Of<INsmProvider>(), new RelayClock()).GetEnclavePublicKey();

        Assert.NotEqual(standalone, diInstance.GetEnclavePublicKey());
    }

    [Fact]
    public void DiContainer_MirroringProgramCs_ProducesUniqueKeysPerContainer()
    {
        // Two separate DI containers must return DIFFERENT public keys —
        // dynamic mode generates fresh RSA per instance.
        IEnclaveKeyService Build()
        {
            var s = new ServiceCollection();
            s.AddSingleton<INsmProvider>(_ => Mock.Of<INsmProvider>());
            s.AddSingleton<RelayClock>();
            s.AddSingleton<IEnclaveKeyService, EnclaveKeyService>();
            return s.BuildServiceProvider().GetRequiredService<IEnclaveKeyService>();
        }

        Assert.NotEqual(Build().GetEnclavePublicKey(), Build().GetEnclavePublicKey());
    }
}
