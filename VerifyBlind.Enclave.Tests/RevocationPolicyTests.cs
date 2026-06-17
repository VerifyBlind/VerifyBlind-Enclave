using System.Collections.Generic;
using VerifyBlind.Core.Models;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// <see cref="RevocationPolicy"/> saf değerlendirme testleri: mutlak aralık, açık uçlar,
/// yuvarlanan maxAge, boş/disabled/bilinmeyen-tip, çoklu kural ve JSON parse (fail-open).
/// </summary>
public class RevocationPolicyTests
{
    private const long Now = 1_800_000_000;       // sabit "şimdi"
    private const long Day = 86_400;

    private static RevocationRule Range(long? from, long? to, bool enabled = true) =>
        new() { Id = "r", Label = "range", Enabled = enabled, Type = "range", FromUnix = from, ToUnix = to };

    private static RevocationRule MaxAge(int days, bool enabled = true) =>
        new() { Id = "m", Label = "maxAge", Enabled = enabled, Type = "maxAge", MaxAgeDays = days };

    // ── range ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Range_IssuedInside_IsRevoked()
    {
        var rules = new[] { Range(1000, 2000) };
        Assert.True(RevocationPolicy.IsRevoked(1500, Now, rules));
        Assert.True(RevocationPolicy.IsRevoked(1000, Now, rules)); // dahil (alt sınır)
        Assert.True(RevocationPolicy.IsRevoked(2000, Now, rules)); // dahil (üst sınır)
    }

    [Fact]
    public void Range_IssuedOutside_IsNotRevoked()
    {
        var rules = new[] { Range(1000, 2000) };
        Assert.False(RevocationPolicy.IsRevoked(999, Now, rules));
        Assert.False(RevocationPolicy.IsRevoked(2001, Now, rules));
    }

    [Fact]
    public void Range_OpenStart_RevokesEverythingUpToTo()
    {
        var rules = new[] { Range(null, 2000) }; // "şu tarihten önce"
        Assert.True(RevocationPolicy.IsRevoked(1, Now, rules));
        Assert.True(RevocationPolicy.IsRevoked(2000, Now, rules));
        Assert.False(RevocationPolicy.IsRevoked(2001, Now, rules));
    }

    [Fact]
    public void Range_OpenEnd_RevokesEverythingFromFrom()
    {
        var rules = new[] { Range(2000, null) };
        Assert.False(RevocationPolicy.IsRevoked(1999, Now, rules));
        Assert.True(RevocationPolicy.IsRevoked(2000, Now, rules));
        Assert.True(RevocationPolicy.IsRevoked(long.MaxValue, Now, rules));
    }

    // ── maxAge ──────────────────────────────────────────────────────────────────

    [Fact]
    public void MaxAge_OlderThanCutoff_IsRevoked()
    {
        var rules = new[] { MaxAge(90) };
        var cutoff = Now - 90 * Day;
        Assert.True(RevocationPolicy.IsRevoked(cutoff - 1, Now, rules));   // daha eski → iptal
        Assert.False(RevocationPolicy.IsRevoked(cutoff, Now, rules));      // tam sınır → iptal değil
        Assert.False(RevocationPolicy.IsRevoked(Now, Now, rules));         // taze → iptal değil
    }

    [Fact]
    public void MaxAge_Zero_RevokesAnyPastTicket()
    {
        var rules = new[] { MaxAge(0) };
        Assert.True(RevocationPolicy.IsRevoked(Now - 1, Now, rules));
        Assert.False(RevocationPolicy.IsRevoked(Now, Now, rules));
    }

    [Fact]
    public void MaxAge_NegativeOrNull_IsIgnored()
    {
        Assert.False(RevocationPolicy.IsRevoked(0, Now, new[] { MaxAge(-1) }));
        var nullDays = new RevocationRule { Type = "maxAge", Enabled = true, MaxAgeDays = null };
        Assert.False(RevocationPolicy.IsRevoked(0, Now, new[] { nullDays }));
    }

    // ── genel ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Empty_IsNotRevoked()
    {
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, new List<RevocationRule>()));
    }

    [Fact]
    public void DisabledRule_IsIgnored()
    {
        var rules = new[] { Range(1000, 2000, enabled: false) };
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, rules));
    }

    [Fact]
    public void UnknownType_IsIgnored()
    {
        var rules = new[] { new RevocationRule { Type = "bogus", Enabled = true, FromUnix = 0, ToUnix = long.MaxValue } };
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, rules));
    }

    [Fact]
    public void MultipleRules_AnyMatch_IsRevoked()
    {
        var rules = new[] { Range(1000, 2000), MaxAge(30) };
        Assert.True(RevocationPolicy.IsRevoked(1500, Now, rules));                    // range eşleşir
        Assert.True(RevocationPolicy.IsRevoked(Now - 31 * Day, Now, rules));          // maxAge eşleşir
        Assert.False(RevocationPolicy.IsRevoked(Now, Now, rules));                    // hiçbiri
    }

    // ── JSON parse (fail-open) ───────────────────────────────────────────────────

    [Fact]
    public void Json_ValidRules_AreEvaluated()
    {
        const string json = "[{\"type\":\"range\",\"enabled\":true,\"fromUnix\":1000,\"toUnix\":2000}]";
        Assert.True(RevocationPolicy.IsRevoked(1500, Now, json));
        Assert.False(RevocationPolicy.IsRevoked(2500, Now, json));
    }

    [Fact]
    public void Json_NullOrEmpty_IsNotRevoked()
    {
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, (string?)null));
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, ""));
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, "   "));
    }

    [Fact]
    public void Json_Malformed_FailsOpen()
    {
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, "{not valid json"));
        Assert.False(RevocationPolicy.IsRevoked(1500, Now, "not-json-at-all"));
    }
}
