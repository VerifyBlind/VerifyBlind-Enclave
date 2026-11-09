using System.Text.Json.Serialization;

namespace VerifyBlind.Core.Models;

/// <summary>
/// Tekil sayım deposu sözleşmesi (relay ↔ enclave). Spec: 2026-11-09-unique-count-store-design.md.
/// Hiçbir alan kişiye ait kod taşımaz: blob'lar yalnız enclave'in açabildiği şifreli metindir,
/// sorgu cevapları yalnız sayıdır.
/// </summary>
public static class CountFamilies
{
    public const string PersonLogin = "person/login";
    public const string PersonRegister = "person/register";
    public const string PartnerPerson = "partner_person";
    public const string Card = "card";

    public static readonly IReadOnlyList<string> All = new[] { PersonLogin, PersonRegister, PartnerPerson, Card };
}

public class CountStoreBlob
{
    [JsonPropertyName("month")] public string Month { get; set; } = string.Empty;     // "YYYY-MM"
    [JsonPropertyName("version")] public long Version { get; set; }
    [JsonPropertyName("blob")] public string Blob { get; set; } = string.Empty;       // base64(nonce||tag||ciphertext)
}

public class CountStoreLoadRequest
{
    [JsonPropertyName("identity_hmac_secret_wrapped")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdentityHmacSecretWrapped { get; set; }

    [JsonPropertyName("blobs")] public List<CountStoreBlob> Blobs { get; set; } = new();
}

public class CountStoreSaveRequest
{
    [JsonPropertyName("identity_hmac_secret_wrapped")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdentityHmacSecretWrapped { get; set; }
}

public class CountStoreSaveResponse
{
    public const string StatusOk = "ok";
    public const string StatusNotLoaded = "not_loaded";

    [JsonPropertyName("status")] public string Status { get; set; } = StatusOk;
    [JsonPropertyName("blobs")] public List<CountStoreBlob> Blobs { get; set; } = new();
}

public class CountStoreQueryRequest
{
    [JsonPropertyName("family")] public string Family { get; set; } = string.Empty;
    [JsonPropertyName("partner_id")] public string? PartnerId { get; set; }
    [JsonPropertyName("from")] public DateOnly From { get; set; }
    [JsonPropertyName("to")] public DateOnly To { get; set; }
}

public class CountStoreQueryResponse
{
    [JsonPropertyName("distinct_count")] public int DistinctCount { get; set; }
}

public class CountStoreDailyRequest
{
    [JsonPropertyName("day")] public DateOnly Day { get; set; }
}

public class CountStoreDailyTotal
{
    [JsonPropertyName("family")] public string Family { get; set; } = string.Empty;
    [JsonPropertyName("partner_id")] public string? PartnerId { get; set; }
    [JsonPropertyName("distinct_count")] public int DistinctCount { get; set; }
}

public class CountStoreDailyResponse
{
    [JsonPropertyName("day")] public DateOnly Day { get; set; }
    [JsonPropertyName("totals")] public List<CountStoreDailyTotal> Totals { get; set; } = new();
}
