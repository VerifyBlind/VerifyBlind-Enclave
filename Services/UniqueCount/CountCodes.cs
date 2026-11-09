using System.Buffers.Binary;

namespace VerifyBlind.Enclave.Services.UniqueCount;

/// <summary>Sayım kümesinin anahtarı. PartnerId yalnız partner_person ailesinde dolu (küçük harf).</summary>
public readonly record struct SetKey(string Family, string? PartnerId);

/// <summary>
/// Tekil sayım kodları (spec 2026-11-09). Etiketler person_id (<c>_Person_id</c>), card_id
/// (<c>_Card_id</c>) ve user_id (<c>{TCKN}:{partnerId}</c>) girdilerinden farklıdır → kodlar onlarla
/// eşleşmez. Kod = HMAC çıktısının ilk 8 baytı (1 milyar kişide beklenen çakışma ~0,03).
/// ⚠️ Kodlar enclave'den ÇIKMAZ ve hiçbir log'a yazılmaz.
/// </summary>
public static class CountCodes
{
    public static ulong Person(IIdentityHmacService hmac, string tckn)
        => First8(hmac.ComputeHmac($"{tckn}_Count_Person"));

    public static ulong PartnerPerson(IIdentityHmacService hmac, string tckn, string partnerId)
        => First8(hmac.ComputeHmac($"{tckn}:{NormalizePartner(partnerId)}_Count_Partner"));

    public static ulong Card(IIdentityHmacService hmac, string sodHashHex)
        => First8(hmac.ComputeHmac($"{sodHashHex}_Count_Card"));

    public static string NormalizePartner(string partnerId) => partnerId.Trim().ToLowerInvariant();

    public static ulong First8(string hmacB64)
        => BinaryPrimitives.ReadUInt64BigEndian(Convert.FromBase64String(hmacB64).AsSpan(0, 8));
}
