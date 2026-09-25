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

    /// <summary>Mağazadaki eski jest akışı kanıt göndermez: kapı çalışmaz (o sürümlerin sözleşmesi).</summary>
    [Fact]
    public void KanitYoksaKapiCalismaz()
    {
        Assert.Null(EnclaveService.ChoreographyGate(new PlanarityOutcome { Status = PlanarityStatuses.NoProof }));
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
