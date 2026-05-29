using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class LocalKmsServiceTests
{
    private static LocalKmsService Build() => new();

    private static TicketPayload MakeTicket(string countryIsoCode = "TUR") => new()
    {
        TCKN = "12345678901",
        Ad = "AHMET",
        Soyad = "YILMAZ",
        DogumTarihi = new DateTime(1990, 1, 1),
        GecerlilikTarihi = new DateTime(2030, 1, 1),
        CountryIsoCode = countryIsoCode,
        UserPubKey = "pubkey-test",
        PersonId = "person-abc",
        CardId = "card-abc",
    };

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

    // ── SignTicketAsync + VerifyTicketSignatureAsync ───────────────────────────

    [Fact]
    public async Task SignAndVerify_TurkishTicket_ReturnsTrue()
    {
        var svc = Build();
        var ticket = MakeTicket("TUR");

        var signature = await svc.SignTicketAsync(ticket);
        Assert.NotEmpty(signature);

        var signedTicket = new SignedTicket { Payload = ticket, Signature = signature };
        var valid = await svc.VerifyTicketSignatureAsync(signedTicket);
        Assert.True(valid);
    }

    [Fact]
    public async Task SignAndVerify_DefaultCountry_ReturnsTrue()
    {
        var svc = Build();
        var ticket = MakeTicket("DEFAULT");

        var sig = await svc.SignTicketAsync(ticket);
        var valid = await svc.VerifyTicketSignatureAsync(new SignedTicket { Payload = ticket, Signature = sig });
        Assert.True(valid);
    }

    [Fact]
    public async Task VerifyTicketSignature_TamperedPayload_ReturnsFalse()
    {
        var svc = Build();
        var ticket = MakeTicket("TUR");
        var sig = await svc.SignTicketAsync(ticket);

        // Tamper payload — change TCKN
        var tampered = MakeTicket("TUR");
        tampered.TCKN = "99999999999";

        var valid = await svc.VerifyTicketSignatureAsync(new SignedTicket { Payload = tampered, Signature = sig });
        Assert.False(valid);
    }

    [Fact]
    public async Task SignAndVerify_UnknownCountry_AutoCreatesKeyAndVerifies()
    {
        var svc = Build();
        var ticket = MakeTicket("DEU"); // not in hardcoded list

        var sig = await svc.SignTicketAsync(ticket);
        Assert.NotEmpty(sig);

        var valid = await svc.VerifyTicketSignatureAsync(new SignedTicket { Payload = ticket, Signature = sig });
        Assert.True(valid);
    }

    [Fact]
    public async Task SignAndVerify_UnknownCountry_SameKeyReusedOnSecondCall()
    {
        var svc = Build();
        var ticket = MakeTicket("FRA");

        // Sign twice — same runtime-generated key → both signatures verify successfully
        var sig1 = await svc.SignTicketAsync(ticket);
        var sig2 = await svc.SignTicketAsync(ticket);

        // RSA-PSS is non-deterministic (randomised salt), so sigs differ; both must verify
        Assert.True(await svc.VerifyTicketSignatureAsync(new SignedTicket { Payload = ticket, Signature = sig1 }));
        Assert.True(await svc.VerifyTicketSignatureAsync(new SignedTicket { Payload = ticket, Signature = sig2 }));
    }

    // ── HMAC Properties ───────────────────────────────────────────────────────

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

    // ── Ticket Signature Forgery Resistance ───────────────────────────────────

    [Fact]
    public async Task SignTicket_HardcodedCountryKey_VerifiesAcrossInstances()
    {
        var ticket = MakeTicket("TUR");
        var sig = await Build().SignTicketAsync(ticket);

        // TUR uses a hardcoded country key — a signature from one instance must verify on another.
        var valid = await Build().VerifyTicketSignatureAsync(new SignedTicket { Payload = ticket, Signature = sig });
        Assert.True(valid);
    }

    [Fact]
    public async Task VerifyTicketSignature_TamperedSignatureBytes_ReturnsFalse()
    {
        var svc = Build();
        var ticket = MakeTicket("TUR");
        var sig = await svc.SignTicketAsync(ticket);

        var sigBytes = Convert.FromBase64String(sig);
        sigBytes[0] ^= 0xFF;

        var valid = await svc.VerifyTicketSignatureAsync(
            new SignedTicket { Payload = ticket, Signature = Convert.ToBase64String(sigBytes) });
        Assert.False(valid);
    }

    [Fact]
    public async Task VerifyTicketSignature_GarbageSignature_ReturnsFalseNeverThrows()
    {
        var svc = Build();
        var valid = await svc.VerifyTicketSignatureAsync(
            new SignedTicket { Payload = MakeTicket("TUR"), Signature = "not-base64!!!" });
        Assert.False(valid);
    }

    [Fact]
    public async Task VerifyTicketSignature_CountryCodeSwapped_ReturnsFalse()
    {
        var svc = Build();
        var sig = await svc.SignTicketAsync(MakeTicket("TUR"));

        // Same identity data, but CountryIsoCode changed → verified against a different
        // country key → must fail. Prevents lifting a signature onto another country's ticket.
        var moved = MakeTicket("TUR");
        moved.CountryIsoCode = "DEU";

        var valid = await svc.VerifyTicketSignatureAsync(new SignedTicket { Payload = moved, Signature = sig });
        Assert.False(valid);
    }

    [Fact]
    public async Task SignTicket_UnknownCountry_RuntimeKeyIsPerInstance()
    {
        // Runtime-generated country keys live in-memory per instance (dev-only behaviour) —
        // a signature from instance A must NOT verify on a fresh instance B.
        var ticket = MakeTicket("ITA");
        var sigFromA = await Build().SignTicketAsync(ticket);

        var validOnB = await Build().VerifyTicketSignatureAsync(
            new SignedTicket { Payload = ticket, Signature = sigFromA });
        Assert.False(validOnB);
    }
}
