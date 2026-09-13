using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// LocalKmsService (dev) artık YALNIZ <see cref="IKmsService.DecryptWithAttestationAsync"/> taşır.
///
/// <para>Eski ComputeHmacAsync testleri <see cref="IdentityHmacServiceTests"/>'e taşındı:
/// takma ad türetme KMS <c>GenerateMac</c>'ten enclave içine alındı. Sebep — AWS'in attestation
/// parametresi (<c>Recipient</c>) MAC işlemlerinde desteklenmediği için o izin EC2
/// instance-role'ünde kalmak zorundaydı ve sunucuya erişen herkes bir TCKN'nin user_id'sini
/// hesaplatabiliyordu.</para>
/// </summary>
public class LocalKmsServiceTests
{
    private static LocalKmsService Build() => new();

    /// <summary>
    /// Dev'de gerçek KMS/Nitro yok → attestation-bound decrypt anlamsız ve DESTEKLENMEMELİ.
    /// Sessizce bir şey döndürmek, prod'da attestation kapısının atlandığını gizlerdi.
    /// </summary>
    [Fact]
    public async Task DecryptWithAttestation_IsNotSupportedInLocalMode()
    {
        var svc = Build();
        await Assert.ThrowsAsync<NotSupportedException>(
            () => svc.DecryptWithAttestationAsync([1, 2, 3], [4, 5, 6], KmsPurpose.IdentityHmac));
    }

    /// <summary>Amaç sabitleri birbirinden farklı olmalı — EncryptionContext ayrımı buna dayanır.</summary>
    [Fact]
    public void KmsPurpose_ValuesAreDistinct()
    {
        Assert.NotEqual(KmsPurpose.TicketMac, KmsPurpose.IdentityHmac);
    }
}
