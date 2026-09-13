using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Moq;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Takma ad türetme HMAC'i (user_id / nsbd_id / doc_id / person_id / card_id).
///
/// <para>Eski <c>LocalKmsServiceTests</c>'in yerini alır: HMAC, KMS <c>GenerateMac</c>'ten
/// enclave içine taşındı. Sebep — AWS'in attestation parametresi MAC işlemlerinde
/// desteklenmediği için izin EC2 instance-role'ünde kalmak zorundaydı ve sunucuya erişen herkes
/// bir TCKN'nin user_id'sini hesaplatabiliyordu.</para>
/// </summary>
public class IdentityHmacServiceTests
{
    /// <summary>Dev modu (KMS_MODE!=aws + Development) — sabit dev secret yolu.</summary>
    private static IdentityHmacService BuildDev()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["KMS_MODE"] = "local" })
            .Build();

        var env = new Mock<IHostEnvironment>();
        env.Setup(e => e.EnvironmentName).Returns("Development");

        return new IdentityHmacService(Mock.Of<IKmsService>(), Mock.Of<IEnclaveKeyService>(), config, env.Object);
    }

    private static async Task<IdentityHmacService> BuildDevLoadedAsync()
    {
        var svc = BuildDev();
        await svc.EnsureSecretLoadedAsync(null);
        return svc;
    }

    // ── Determinizm ───────────────────────────────────────────────────────────

    [Fact]
    public async Task ComputeHmac_SameInput_ReturnsSameValue()
    {
        var svc = await BuildDevLoadedAsync();
        Assert.Equal(svc.ComputeHmac("hello"), svc.ComputeHmac("hello"));
    }

    [Fact]
    public async Task ComputeHmac_DifferentInput_ReturnsDifferentValue()
    {
        var svc = await BuildDevLoadedAsync();
        Assert.NotEqual(svc.ComputeHmac("aaa"), svc.ComputeHmac("bbb"));
    }

    /// <summary>
    /// Çıktı biçimi KORUNMALI: base64(HMAC-SHA256) = 32 bayt → 44 karakter.
    /// user_id bu değeri DOĞRUDAN kullanır; person_id/card_id/nsbd_id/doc_id ise
    /// hex(SHA256(base64'ten çözülmüş bayt)) sarmalar. Biçim değişirse ikisi de bozulur.
    /// </summary>
    [Fact]
    public async Task ComputeHmac_ReturnsBase64Of32Bytes()
    {
        var svc = await BuildDevLoadedAsync();
        var raw = Convert.FromBase64String(svc.ComputeHmac("anything"));
        Assert.Equal(32, raw.Length);
    }

    // ── Domain separation ─────────────────────────────────────────────────────

    /// <summary>
    /// Kimlik-HMAC ile ticket-MAC AYNI dev secret türetme kalıbını kullanmaz; ayrıca farklı
    /// domain etiketi taşır ("vb-idhmac-v1\n" ≠ "vb-ticket-v1\n"). Aynı girdi için iki servisin
    /// aynı çıktıyı vermesi, sırların/etiketlerin karıştığı anlamına gelirdi.
    /// </summary>
    [Fact]
    public async Task ComputeHmac_DiffersFromTicketMacSecretDerivation()
    {
        var idSvc = await BuildDevLoadedAsync();

        // Ticket-MAC'in dev secret'i farklı bir sabitten türer; aynı girdi farklı sonuç vermeli.
        using var ticketHmac = new System.Security.Cryptography.HMACSHA256(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes("verifyblind-ticket-mac-dev-secret-v1")));
        var ticketSide = Convert.ToBase64String(
            ticketHmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes("collision-probe")));

        Assert.NotEqual(ticketSide, idSvc.ComputeHmac("collision-probe"));
    }

    // ── Fail-closed davranışlar ───────────────────────────────────────────────

    [Fact]
    public void ComputeHmac_BeforeSecretLoaded_Throws()
    {
        var svc = BuildDev();
        Assert.Throws<InvalidOperationException>(() => svc.ComputeHmac("x"));
    }

    /// <summary>
    /// DEV secret kaynak kodda sabit → prod'da kullanılırsa takma adlar herkesçe yeniden
    /// hesaplanabilir hale gelir (tam da kapatılan açık). Development dışında REDDEDİLMELİ.
    /// </summary>
    [Fact]
    public async Task EnsureSecretLoaded_DevSecretOutsideDevelopment_Throws()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["KMS_MODE"] = "local" })
            .Build();

        var env = new Mock<IHostEnvironment>();
        env.Setup(e => e.EnvironmentName).Returns("Production");

        var svc = new IdentityHmacService(Mock.Of<IKmsService>(), Mock.Of<IEnclaveKeyService>(), config, env.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.EnsureSecretLoadedAsync(null));
    }

    /// <summary>AWS modunda blob gelmezse fail-closed — sessizce dev secret'a DÜŞMEMELİ.</summary>
    [Fact]
    public async Task EnsureSecretLoaded_AwsModeWithoutBlob_Throws()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["KMS_MODE"] = "aws" })
            .Build();

        var env = new Mock<IHostEnvironment>();
        env.Setup(e => e.EnvironmentName).Returns("Production");

        var svc = new IdentityHmacService(Mock.Of<IKmsService>(), Mock.Of<IEnclaveKeyService>(), config, env.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.EnsureSecretLoadedAsync(null));
    }

    /// <summary>İkinci yükleme çağrısı no-op olmalı (idempotent, boot başına 1 kez).</summary>
    [Fact]
    public async Task EnsureSecretLoaded_IsIdempotent()
    {
        var svc = await BuildDevLoadedAsync();
        var before = svc.ComputeHmac("stable");
        await svc.EnsureSecretLoadedAsync(null);
        Assert.Equal(before, svc.ComputeHmac("stable"));
    }
}
