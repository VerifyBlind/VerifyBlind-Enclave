using System.Text.RegularExpressions;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// nsbd_id / doc_id türetim testleri. Kanonikleştirme (saf) + KMS-tabanlı derivasyon özellikleri:
/// kart-yenilemede sabitlik, partner-scope, sert/olasılıksal sinyal davranışı.
/// </summary>
public class IdentityCodesTests
{
    private static LocalKmsService Kms() => new();

    private static TicketPayload Payload(
        string uyruk = "TUR", string country = "TUR",
        string soyad = "YILMAZ", string ad = "MEHMET ALI",
        int year = 1990, int month = 1, int day = 5,
        string cinsiyet = "M", string seriNo = "A12345678",
        string cardId = "card-aaa", string? docType = "I")
        => new()
        {
            Uyruk = uyruk,
            CountryIsoCode = country,
            Soyad = soyad,
            Ad = ad,
            DogumTarihi = year == 0 ? DateTime.MinValue : new DateTime(year, month, day),
            Cinsiyet = cinsiyet,
            SeriNo = seriNo,
            CardId = cardId,
            DocumentType = docType,
        };

    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$");

    // ── Kanonikleştirme (saf) ─────────────────────────────────────────────────

    [Fact]
    public void Canonical_IsDeterministic()
        => Assert.Equal(IdentityCodes.BuildNsbdCanonical(Payload()), IdentityCodes.BuildNsbdCanonical(Payload()));

    [Fact]
    public void Canonical_StartsWithVersionMarker()
        => Assert.StartsWith(IdentityCodes.NsbdVersion + "_", IdentityCodes.BuildNsbdCanonical(Payload()));

    [Fact]
    public void Canonical_HasExpectedShape()
        => Assert.Equal("NSBD1_TUR_YILMAZ_MEHMET ALI_19900105_M", IdentityCodes.BuildNsbdCanonical(Payload()));

    [Fact]
    public void Canonical_IsCaseInsensitive()
        => Assert.Equal(
            IdentityCodes.BuildNsbdCanonical(Payload(soyad: "YILMAZ", ad: "MEHMET")),
            IdentityCodes.BuildNsbdCanonical(Payload(soyad: "yilmaz", ad: "mehmet")));

    [Fact]
    public void Canonical_CollapsesAndTrimsWhitespace()
        => Assert.Equal(
            IdentityCodes.BuildNsbdCanonical(Payload(ad: "MEHMET ALI")),
            IdentityCodes.BuildNsbdCanonical(Payload(ad: "  MEHMET   ALI  ")));

    [Fact]
    public void Canonical_StripsNonAlpha()
    {
        // Noktalama (') ve rakam (2) atılır; harfler korunur.
        Assert.Equal("NSBD1_TUR_OCONNOR_MEHMET ALI_19900105_M",
            IdentityCodes.BuildNsbdCanonical(Payload(soyad: "O'Connor", ad: "Mehmet2 Ali")));
    }

    [Fact]
    public void Canonical_EmptyWhenNationalityEmpty_NoCountryFallback()
        // Uyruk (MRZ nationality) boşsa CountryIsoCode'a düşülMEZ → boş döner.
        => Assert.Equal("", IdentityCodes.BuildNsbdCanonical(Payload(uyruk: "", country: "DEU")));

    [Fact]
    public void Canonical_MapsUnknownGenderToX()
    {
        // M/F dışındaki cinsiyet ("<", "X", boş) "X" token'ına eşlenir; nsbd_id yine üretilir.
        Assert.Equal("NSBD1_TUR_YILMAZ_MEHMET ALI_19900105_X",
            IdentityCodes.BuildNsbdCanonical(Payload(cinsiyet: "<")));
        Assert.Equal(
            IdentityCodes.BuildNsbdCanonical(Payload(cinsiyet: "<")),
            IdentityCodes.BuildNsbdCanonical(Payload(cinsiyet: "")));
    }

    [Fact]
    public void Canonical_EmptyWhenNoNames()
        => Assert.Equal("", IdentityCodes.BuildNsbdCanonical(Payload(soyad: "", ad: "")));

    [Fact]
    public void Canonical_EmptyWhenNoNationalityOrCountry()
        => Assert.Equal("", IdentityCodes.BuildNsbdCanonical(Payload(uyruk: "", country: "")));

    [Fact]
    public void Canonical_EmptyWhenDobInvalid()
        => Assert.Equal("", IdentityCodes.BuildNsbdCanonical(Payload(year: 0)));

    [Fact]
    public void Canonical_NonAsciiDeterministicNotThrow()
    {
        // Demo kimliği "Kullanıcı" (Türkçe ı) gibi non-ASCII → patlamadan deterministik string üretmeli.
        var a = IdentityCodes.BuildNsbdCanonical(Payload(soyad: "Kullanıcı", ad: "Demo"));
        var b = IdentityCodes.BuildNsbdCanonical(Payload(soyad: "Kullanıcı", ad: "Demo"));
        Assert.Equal(a, b);
        Assert.NotEqual("", a);
    }

    // ── nsbd_id türetimi (KMS) ────────────────────────────────────────────────

    [Fact]
    public async Task NsbdId_IsLowercaseHex64()
    {
        var nsbd = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(), "partner-1");
        Assert.NotNull(nsbd);
        Assert.Matches(Hex64, nsbd);
    }

    [Fact]
    public async Task NsbdId_StableAcrossCardRenewal()
    {
        // Aynı kişi (aynı bio), farklı kart (SeriNo + CardId değişti) → AYNI nsbd_id olmalı.
        var oldCard = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(seriNo: "A111", cardId: "card-old"), "p1");
        var newCard = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(seriNo: "B222", cardId: "card-new"), "p1");
        Assert.Equal(oldCard, newCard);
    }

    [Fact]
    public async Task NsbdId_IsPartnerScoped()
    {
        var p1 = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(), "partner-1");
        var p2 = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(), "partner-2");
        Assert.NotEqual(p1, p2);
    }

    [Fact]
    public async Task NsbdId_DiffersForDifferentPerson()
    {
        var a = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(soyad: "YILMAZ"), "p1");
        var b = await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(soyad: "KAYA"), "p1");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task NsbdId_NullWhenPartnerIdEmpty()
        => Assert.Null(await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(), ""));

    [Fact]
    public async Task NsbdId_NullWhenCanonicalEmpty()
        => Assert.Null(await IdentityCodes.BuildNsbdIdAsync(Kms(), Payload(soyad: "", ad: ""), "p1"));

    // ── doc_id türetimi (KMS) ─────────────────────────────────────────────────

    [Fact]
    public async Task DocId_HasDocTypePrefixAndHex64()
    {
        var doc = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", "p1");
        Assert.NotNull(doc);
        Assert.StartsWith("I_", doc);
        Assert.Matches(Hex64, doc!["I_".Length..]);
    }

    [Fact]
    public async Task DocId_SameCardSamePartner_IsStable()
    {
        var a = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", "p1");
        var b = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", "p1");
        Assert.Equal(a, b); // aynı belge + aynı partner ⟹ aynı kişi (sert sinyal)
    }

    [Fact]
    public async Task DocId_IsPartnerScoped()
    {
        var p1 = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", "p1");
        var p2 = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", "p2");
        Assert.NotEqual(p1, p2);
    }

    [Fact]
    public async Task DocId_DiffersForDifferentCard()
    {
        var a = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", "p1");
        var b = await IdentityCodes.BuildDocIdAsync(Kms(), "card-bbb", "I", "p1");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task DocId_UsesXPrefixWhenDocTypeMissing()
    {
        var doc = await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", null, "p1");
        Assert.StartsWith("X_", doc);
    }

    [Fact]
    public async Task DocId_NullWhenCardIdEmpty()
        => Assert.Null(await IdentityCodes.BuildDocIdAsync(Kms(), "", "I", "p1"));

    [Fact]
    public async Task DocId_NullWhenPartnerIdEmpty()
        => Assert.Null(await IdentityCodes.BuildDocIdAsync(Kms(), "card-aaa", "I", ""));

    // ── PIN tabanlı person_id türetimi (KMS) ──────────────────────────────────
    // TCKN'siz kimliklerin bulut yedek anahtarı (KEK) buradan türer. TCKN yolundan
    // ("{TCKN}_Person_id") domain separation ile ayrıktır.

    [Fact]
    public async Task PinPersonId_IsLowercaseHex64()
    {
        var pid = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", "550e8400-e29b-41d4-a716-446655440000");
        Assert.NotNull(pid);
        Assert.Matches(Hex64, pid);
    }

    [Fact]
    public async Task PinPersonId_IsDeterministic()
    {
        // Aynı PIN + aynı UUID ⟹ aynı kod. Yedek şifresinin çözülebilmesi buna dayanır.
        var a = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", "uuid-fixed");
        var b = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", "uuid-fixed");
        Assert.Equal(a, b);
    }

    [Fact]
    public async Task PinPersonId_DiffersForDifferentUuid()
    {
        // UUID per-user salt: aynı PIN'i seçen iki kullanıcı AYNI kodu üretmemeli,
        // yoksa birbirlerinin yedeğini çözebilirlerdi.
        var a = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", "uuid-a");
        var b = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", "uuid-b");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task PinPersonId_DiffersForDifferentPin()
    {
        var a = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", "uuid-fixed");
        var b = await IdentityCodes.BuildPinPersonIdAsync(Kms(), "654321", "uuid-fixed");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task PinPersonId_NullWhenPinEmpty()
        => Assert.Null(await IdentityCodes.BuildPinPersonIdAsync(Kms(), "", "uuid-fixed"));

    [Fact]
    public async Task PinPersonId_NullWhenUuidEmpty()
        => Assert.Null(await IdentityCodes.BuildPinPersonIdAsync(Kms(), "123456", ""));

    [Fact]
    public async Task PinPersonId_IsDomainSeparatedFromTcknPath()
    {
        // TCKN yolu HMAC("{TCKN}_Person_id"), PIN yolu HMAC("VBPIN1|{pin}|{uuid}").
        // Bir kullanıcı PIN olarak bir TCKN yazsa bile o TCKN'nin person_id'siyle ÇAKIŞMAMALI.
        var kms = Kms();
        const string tckn = "12345678901";

        var tcknHmac = await kms.ComputeHmacAsync($"{tckn}_Person_id");
        var tcknPersonId = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(tcknHmac))
        ).ToLowerInvariant();

        var pinPersonId = await IdentityCodes.BuildPinPersonIdAsync(kms, tckn, "any-uuid");

        Assert.NotEqual(tcknPersonId, pinPersonId);
    }

    [Fact]
    public void PinVersion_IsVbpin1()
        => Assert.Equal("VBPIN1", IdentityCodes.PinVersion);
}
