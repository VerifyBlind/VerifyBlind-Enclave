using VerifyBlind.Core;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.Stance;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Geometri + kimlik kapılarının SIRASI ve KODLARI.
///
/// <para>Sıra kullanıcıya gösterilecek mesajı belirliyor: duvar dibindeki meşru kullanıcıya
/// "yüzünüz eşleşmedi" demek onu yanlış şeyi düzeltmeye yollar. Parallaks kimlikten önce.</para>
/// </summary>
public class StanceGateTests
{
    private static PlanarityOutcome Measured(double p = 0.6, double texture = 30) => new()
    {
        Status = PlanarityStatuses.Measured,
        NearResidual = p,
        BgTexture = texture,
    };

    private static ChoreographyOutcome Choreo(double? identityMin = 0.55) => new()
    {
        Status = ChoreographyVerifier.StatusMeasured,
        IdentityMin = identityMin,
    };

    [Fact]
    public void MesruAkisGecer()
    {
        var p = Measured();
        p.Choreography = Choreo();
        Assert.Null(EnclaveService.StanceGate(p));
    }

    [Fact]
    public void EskiKanittaOlculemeyenAkisGecer()
    {
        // Eski kanıt katı değil: no_texture / not_approached geçer (mağazadaki sürümün sözleşmesi).
        Assert.Null(EnclaveService.StanceGate(new PlanarityOutcome { Status = PlanarityStatuses.NoTexture }));
        Assert.Null(EnclaveService.StanceGate(new PlanarityOutcome { Status = PlanarityStatuses.NoProof }));
    }

    [Fact]
    public void BozukYapiHerSeydenOnceReddedilir()
    {
        var p = Measured(p: -0.05, texture: 10);        // düz VE dokusuz — yine de yapı kazanır
        p.Choreography = new ChoreographyOutcome
        {
            Status = ChoreographyVerifier.StatusInvalid,
            InvalidReason = "stops",
            IdentityMin = 0.0,
        };

        var ex = EnclaveService.StanceGate(p);
        Assert.Equal(EnclaveErrorCodes.ChoreographyInvalid, ex!.ErrorCode);
        Assert.Same(p, ex.Planarity);
    }

    [Theory]
    [InlineData(PlanarityStatuses.FlatSurface, 30.0, EnclaveErrorCodes.ParallaxFlat)]
    [InlineData(PlanarityStatuses.FlatSurface, 10.0, EnclaveErrorCodes.ParallaxBare)]
    [InlineData(PlanarityStatuses.Unmeasured, 30.0, EnclaveErrorCodes.ParallaxFlat)]
    [InlineData(PlanarityStatuses.Unmeasured, 10.0, EnclaveErrorCodes.ParallaxBare)]
    public void ParallaksMesajiDokudanSecilir(string status, double texture, string expected)
    {
        var p = new PlanarityOutcome { Status = status, BgTexture = texture };
        Assert.Equal(expected, EnclaveService.StanceGate(p)!.ErrorCode);
    }

    /// <summary>Duvar dibi + başkasının yüzü: kullanıcıya önce parallaks söylenir.</summary>
    [Fact]
    public void ParallaksKimliktenOnceGelir()
    {
        var p = new PlanarityOutcome { Status = PlanarityStatuses.FlatSurface, BgTexture = 30 };
        p.Choreography = Choreo(identityMin: 0.02);
        Assert.Equal(EnclaveErrorCodes.ParallaxFlat, EnclaveService.StanceGate(p)!.ErrorCode);
    }

    [Fact]
    public void KaynakAyrimiKimliktenReddedilir()
    {
        var p = Measured();
        p.Choreography = Choreo(identityMin: 0.05);

        var ex = EnclaveService.StanceGate(p);
        Assert.Equal(EnclaveErrorCodes.ChoreographyIdentity, ex!.ErrorCode);
        Assert.Equal(0.05f, ex.FaceScore!.Value, 3);
    }

    [Fact]
    public void KimlikEsigiAdaylarlaAyni()
    {
        var justAbove = Measured();
        justAbove.Choreography = Choreo(identityMin: EnclaveService.BiometricThreshold + 0.001);
        Assert.Null(EnclaveService.StanceGate(justAbove));

        var justBelow = Measured();
        justBelow.Choreography = Choreo(identityMin: EnclaveService.BiometricThreshold - 0.001);
        Assert.NotNull(EnclaveService.StanceGate(justBelow));
    }

    /// <summary>
    /// Kimlik ölçülemediyse (DG2 yüzü çıkmadı, model yok) bu kapı çalışmaz — fail-open DEĞİL:
    /// aynı çıkarım aday değerlendirmesinde fail-closed tekrarlanıyor.
    /// </summary>
    [Fact]
    public void KimlikOlculmediyseBuKapiCalismaz()
    {
        var p = Measured();
        p.Choreography = Choreo(identityMin: null);
        Assert.Null(EnclaveService.StanceGate(p));
    }
}
