using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Moq;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Golden-vector tests that PIN the Ticket-MAC wire form. The MAC is computed over the DEFAULT
/// System.Text.Json serialization of <see cref="TicketPayload"/>. If TicketPayload's shape changes
/// (field added / removed / renamed / reordered / retyped) these tests break — that is the alarm:
/// every ticket already issued in production would be invalidated, because each ticket's MAC was
/// computed over the OLD serialization. See the warning above TicketPayload in SharedModels.cs.
/// </summary>
public class TicketMacServiceTests
{
    // Fixed identity → fixed wire form → fixed MAC. Do NOT edit these to make a failing test pass.
    private static TicketPayload GoldenPayload() => new()
    {
        TCKN = "12345678901",
        Ad = "AHMET",
        Soyad = "YILMAZ",
        DogumTarihi = new DateTime(1990, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
        SeriNo = "A12345678",
        GecerlilikTarihi = new DateTime(2030, 12, 31, 0, 0, 0, DateTimeKind.Unspecified),
        Cinsiyet = "M",
        Uyruk = "TUR",
        UserPubKey = "GOLDEN_PUBKEY",
        CountryIsoCode = "TUR",
        PersonId = "person-fixed",
        CardId = "card-fixed",
        DocumentType = "I"
    };

    // Dev-mode service: KMS_MODE != "aws" → deterministic dev secret (no KMS / Nitro needed).
    private static TicketMacService DevService()
    {
        var config = new Mock<IConfiguration>();
        config.Setup(c => c["KMS_MODE"]).Returns((string?)null);
        return new TicketMacService(new Mock<IKmsService>().Object, new Mock<IEnclaveKeyService>().Object, config.Object);
    }

    [Fact]
    public void TicketPayload_SerializesToGoldenWireForm()
    {
        // The exact JSON the MAC is taken over. A diff here means the ticket wire form changed.
        const string goldenJson =
            "{\"TCKN\":\"12345678901\",\"Ad\":\"AHMET\",\"Soyad\":\"YILMAZ\"," +
            "\"DogumTarihi\":\"1990-01-01T00:00:00\",\"SeriNo\":\"A12345678\"," +
            "\"GecerlilikTarihi\":\"2030-12-31T00:00:00\",\"Cinsiyet\":\"M\",\"Uyruk\":\"TUR\"," +
            "\"UserPubKey\":\"GOLDEN_PUBKEY\",\"CountryIsoCode\":\"TUR\"," +
            "\"PersonId\":\"person-fixed\",\"CardId\":\"card-fixed\",\"DocumentType\":\"I\"}";

        Assert.Equal(goldenJson, JsonSerializer.Serialize(GoldenPayload()));
    }

    [Fact]
    public async Task ComputeMac_GoldenVector_IsStableUnderDevSecret()
    {
        var svc = DevService();
        await svc.EnsureSecretLoadedAsync(null);

        // Dev secret = SHA256("verifyblind-ticket-mac-dev-secret-v1"); domain label = "vb-ticket-v1\n".
        // HMAC-SHA256 over (label || goldenJson), Base64. Recompute ONLY if the wire form
        // intentionally changed (and understand that this breaks every existing production ticket).
        const string expectedMac = "op/NjncsPx4wRBrPMZyn9dBQavB6FRdvuYAiSOlmc2Y=";
        Assert.Equal(expectedMac, svc.ComputeMac(GoldenPayload()));
    }

    [Fact]
    public async Task VerifyMac_AcceptsMatchingMac()
    {
        var svc = DevService();
        await svc.EnsureSecretLoadedAsync(null);

        var signed = new SignedTicket { Payload = GoldenPayload(), Signature = svc.ComputeMac(GoldenPayload()) };
        Assert.True(svc.VerifyMac(signed));
    }

    [Fact]
    public async Task VerifyMac_RejectsTamperedPayload()
    {
        var svc = DevService();
        await svc.EnsureSecretLoadedAsync(null);

        var mac = svc.ComputeMac(GoldenPayload());
        var tampered = GoldenPayload();
        tampered.TCKN = "99999999999"; // flip one field — MAC must no longer verify
        Assert.False(svc.VerifyMac(new SignedTicket { Payload = tampered, Signature = mac }));
    }

    [Fact]
    public async Task VerifyMac_RejectsGarbageSignature()
    {
        var svc = DevService();
        await svc.EnsureSecretLoadedAsync(null);
        Assert.False(svc.VerifyMac(new SignedTicket { Payload = GoldenPayload(), Signature = "not-base64-!!!" }));
    }
}
