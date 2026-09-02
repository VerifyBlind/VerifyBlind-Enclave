using System.Text.Json;
using System.Text.Json.Serialization;

namespace VerifyBlind.Core.Models;

/// <summary>
/// Tek bir ticket-iptal kuralı. Admin panelden yönetilir, system_settings['ticket_revocation_rules']
/// içinde JSON dizisi olarak saklanır, login'de relay tarafından (yalnız etkin olanlar) enclave'e
/// iletilir. Enclave, ticket'ın <see cref="TicketPayload.SignedAtUnix"/>'ini bu kurallara karşı
/// <see cref="RevocationPolicy"/> ile değerlendirir. Gizli değildir.
///
/// JSON alan adları camelCase olarak SABİT'tir ([JsonPropertyName]) → relay↔enclave serileştirmesi
/// serializer opsiyonlarından bağımsız uyumludur.
/// </summary>
public sealed class RevocationRule
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("label")]
    public string Label { get; set; } = "";

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>"range" (mutlak from/to) veya "maxAge" (yuvarlanan x günden eski).</summary>
    [JsonPropertyName("type")]
    public string Type { get; set; } = "range";

    /// <summary>type=range: aralık başlangıcı (Unix saniye). null = açık başlangıç.</summary>
    [JsonPropertyName("fromUnix")]
    public long? FromUnix { get; set; }

    /// <summary>type=range: aralık sonu (Unix saniye, dahil). null = açık son.</summary>
    [JsonPropertyName("toUnix")]
    public long? ToUnix { get; set; }

    /// <summary>type=maxAge: bu gün sayısından eski ticket'lar reddedilir (login anında now-N'e göre).</summary>
    [JsonPropertyName("maxAgeDays")]
    public int? MaxAgeDays { get; set; }
}

/// <summary>
/// Ticket-iptal kurallarının saf (yan-etkisiz) değerlendirmesi. Enclave login'de kullanır.
/// Tasarım kararı: <b>fail-open</b> — ayrıştırılamayan JSON veya geçersiz tek kural, o login'i
/// kilitlememek için "eşleşme yok" (kabul) sayılır. Kurallar admin (güvenilir) tarafından girilir
/// ve UI doğrular; bozuk kural bir operasyon hatasıdır, saldırı değil. "Kural yok = kabul" ilkesiyle
/// tutarlı.
/// </summary>
public static class RevocationPolicy
{
    /// <summary>Ham kural JSON'unu parse edip değerlendirir. JSON boş/bozuksa false (iptal değil).</summary>
    public static bool IsRevoked(long signedAtUnix, long nowUnix, string? rulesJson)
    {
        if (string.IsNullOrWhiteSpace(rulesJson)) return false;
        List<RevocationRule>? rules;
        try
        {
            rules = JsonSerializer.Deserialize<List<RevocationRule>>(rulesJson);
        }
        catch
        {
            // Bozuk kural seti → fail-open (login'i kilitleme). Çağıran taraf loglamalı.
            return false;
        }
        return rules != null && IsRevoked(signedAtUnix, nowUnix, rules);
    }

    /// <summary>Etkin kurallardan herhangi biri eşleşirse ticket iptal edilmiştir.</summary>
    public static bool IsRevoked(long signedAtUnix, long nowUnix, IEnumerable<RevocationRule> rules)
    {
        foreach (var rule in rules)
        {
            if (Matches(signedAtUnix, nowUnix, rule)) return true;
        }
        return false;
    }

    private static bool Matches(long signedAtUnix, long nowUnix, RevocationRule rule)
    {
        if (rule == null || !rule.Enabled) return false;

        switch (rule.Type)
        {
            case "range":
                var fromOk = rule.FromUnix is null || signedAtUnix >= rule.FromUnix.Value;
                var toOk = rule.ToUnix is null || signedAtUnix <= rule.ToUnix.Value;
                return fromOk && toOk;

            case "maxAge":
                if (rule.MaxAgeDays is null || rule.MaxAgeDays.Value < 0) return false; // geçersiz → atla
                var cutoff = nowUnix - (long)rule.MaxAgeDays.Value * 86_400L;
                return signedAtUnix < cutoff;

            default:
                return false; // bilinmeyen tip → atla
        }
    }
}
