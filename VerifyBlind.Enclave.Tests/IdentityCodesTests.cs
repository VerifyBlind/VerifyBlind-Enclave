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

    // ── IsValidTckn ───────────────────────────────────────────────────────────
    // Bu kapı olmadan geçersiz/eksik TCKN sessizce boş user_id üretiyordu ve TCKN'siz TÜM
    // kullanıcılar partner tarafında aynı kimliğe çakışıyordu.

    [Theory]
    [InlineData("12345678901")]
    [InlineData("98765432109")]
    public void IsValidTckn_ElevenDigitsNotStartingWithZero_IsValid(string tckn)
        => Assert.True(IdentityCodes.IsValidTckn(tckn));

    [Theory]
    [InlineData(null)]          // hiç yok
    [InlineData("")]            // boş — eski "sessiz boş user_id" yolu
    [InlineData("1234567890")]  // 10 hane
    [InlineData("123456789012")]// 12 hane
    [InlineData("01234567890")] // 0 ile başlıyor — geçerli bir TCKN olamaz
    [InlineData("1234567890A")] // harf içeriyor
    [InlineData("12345 678901")]// boşluk içeriyor
    public void IsValidTckn_MalformedInput_IsInvalid(string? tckn)
        => Assert.False(IdentityCodes.IsValidTckn(tckn));
}
