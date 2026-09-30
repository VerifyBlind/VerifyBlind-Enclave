using VerifyBlind.Core;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.Liveness;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Olay dizisi kapısının SIRASI ve KODLARI.
///
/// <para>Yapı önce: kanıt istenen diziyle uyuşmuyorsa kimlik sayıları neye göre ölçüldüğü
/// belirsiz sayılardır.</para>
/// </summary>
public class ChoreographyGateTests
{
    private static PlanarityOutcome Sequence(double? identityMin = 0.55, string status = ChoreographyVerifier.StatusMeasured) => new()
    {
        Status = PlanarityStatuses.Measured,
        Choreography = new ChoreographyOutcome { Status = status, IdentityMin = identityMin },
    };

    [Fact]
    public void MesruAkisGecer()
    {
        Assert.Null(EnclaveService.ChoreographyGate(Sequence()));
    }

    /// <summary>2026-09-30'dan beri kanıt zorunlu: kanıtsız kayıt reddedilir (yeni kod yok, ChoreographyInvalid).</summary>
    [Fact]
    public void KanitYoksaReddedilir()
    {
        var p = new PlanarityOutcome { Status = PlanarityStatuses.NoProof };

        var ex = EnclaveService.ChoreographyGate(p);
        Assert.Equal(EnclaveErrorCodes.ChoreographyInvalid, ex!.ErrorCode);
        Assert.Same(p, ex.Planarity);
    }

    /// <summary>Ölçüm yoksa durum etiketi ne olursa olsun red — kapıyı atlatan bir yol kalmamalı.</summary>
    [Theory]
    [InlineData(PlanarityStatuses.NoProof)]
    [InlineData(PlanarityStatuses.Unmeasured)]
    [InlineData(PlanarityStatuses.Measured)]
    public void OlcumYoksaHerDurumdaReddedilir(string status)
    {
        var ex = EnclaveService.ChoreographyGate(new PlanarityOutcome { Status = status });
        Assert.Equal(EnclaveErrorCodes.ChoreographyInvalid, ex!.ErrorCode);
    }

    [Fact]
    public void BozukYapiKimliktenOnceReddedilir()
    {
        var p = Sequence(identityMin: 0.0, status: ChoreographyVerifier.StatusInvalid);
        p.Choreography!.InvalidReason = "steps";

        var ex = EnclaveService.ChoreographyGate(p);
        Assert.Equal(EnclaveErrorCodes.ChoreographyInvalid, ex!.ErrorCode);
        Assert.Same(p, ex.Planarity);
    }

    [Fact]
    public void KaynakAyrimiKimliktenReddedilir()
    {
        var p = Sequence(identityMin: 0.05);

        var ex = EnclaveService.ChoreographyGate(p);
        Assert.Equal(EnclaveErrorCodes.ChoreographyIdentity, ex!.ErrorCode);
        Assert.Equal(0.05f, ex.FaceScore!.Value, 3);
        Assert.Same(p, ex.Planarity);
    }

    [Fact]
    public void KimlikEsigiAdaylarlaAyni()
    {
        Assert.Null(EnclaveService.ChoreographyGate(Sequence(EnclaveService.BiometricThreshold + 0.001)));
        Assert.NotNull(EnclaveService.ChoreographyGate(Sequence(EnclaveService.BiometricThreshold - 0.001)));
    }

    /// <summary>
    /// Kimlik ölçülemediyse (DG2 yüzü çıkmadı, model yok) bu kapı çalışmaz — fail-open DEĞİL:
    /// aynı çıkarım aday değerlendirmesinde fail-closed tekrarlanıyor.
    /// </summary>
    [Fact]
    public void KimlikOlculmediyseBuKapiCalismaz()
    {
        Assert.Null(EnclaveService.ChoreographyGate(Sequence(identityMin: null)));
    }
}
