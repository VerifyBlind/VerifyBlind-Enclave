using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

// Ticket imzalama enclave-içi MAC'e taşındı (Ticket Forgery fix) → LocalKmsService artık sadece HMAC.
// Eski SignTicket/VerifyTicketSignature testleri kaldırıldı (o metodlar silindi).
public class LocalKmsServiceTests
{
    private static LocalKmsService Build() => new();

    // ── ComputeHmacAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task ComputeHmacAsync_SameInput_ReturnsSameHash()
    {
        var svc = Build();
        var h1 = await svc.ComputeHmacAsync("hello");
        var h2 = await svc.ComputeHmacAsync("hello");
        Assert.Equal(h1, h2);
    }

    [Fact]
    public async Task ComputeHmacAsync_DifferentInput_ReturnsDifferentHash()
    {
        var svc = Build();
        var h1 = await svc.ComputeHmacAsync("aaa");
        var h2 = await svc.ComputeHmacAsync("bbb");
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public async Task ComputeHmacAsync_ReturnsValidBase64()
    {
        var svc = Build();
        var result = await svc.ComputeHmacAsync("test-data");
        var bytes = Convert.FromBase64String(result);
        Assert.Equal(32, bytes.Length); // HMAC-SHA256 = 32 bytes
    }

    [Fact]
    public async Task ComputeHmacAsync_EmptyString_ReturnsHash()
    {
        var svc = Build();
        var result = await svc.ComputeHmacAsync("");
        Assert.NotEmpty(result);
    }

    [Fact]
    public async Task ComputeHmac_OutputDiffersFromInput()
    {
        var svc = Build();
        Assert.NotEqual("plain-text", await svc.ComputeHmacAsync("plain-text"));
    }

    [Fact]
    public async Task ComputeHmac_StaticKey_IdenticalAcrossInstances()
    {
        // HmacKey is a static field — person_id / user_id / card_id derivations must be
        // reproducible across instances (and process restarts), otherwise IDs would not be stable.
        var a = await Build().ComputeHmacAsync("12345678901_Person_id");
        var b = await Build().ComputeHmacAsync("12345678901_Person_id");
        Assert.Equal(a, b);
    }

    [Fact]
    public async Task ComputeHmac_LongInput_ReturnsFixed32ByteHash()
    {
        var svc = Build();
        var result = await svc.ComputeHmacAsync(new string('x', 50_000));
        Assert.Equal(32, Convert.FromBase64String(result).Length);
    }
}
