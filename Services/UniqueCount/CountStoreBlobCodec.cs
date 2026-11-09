using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services.UniqueCount;

/// <summary>Blob açılamadı/bozuk. Mesaj kişisel veri ya da kod içermez.</summary>
public sealed class CountStoreBlobException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Bir ayın sayım kümeleri ↔ şifreli blob (spec 2026-11-09).
/// AES-256-GCM, her şifrelemede yeni rastgele nonce → içerik değişmese de şifreli metin farklı.
/// Düz metin <see cref="PadBlock"/> katına dolgulanır → boyut yeni kişide değişmez.
/// AAD ay + sürümü bağlar → relay blob'u başka aya taşıyamaz, sürüm etiketini değiştiremez.
/// Çıktı: base64(nonce[12] || tag[16] || şifreli metin).
/// </summary>
public static class CountStoreBlobCodec
{
    public const int PadBlock = 256 * 1024;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const byte FormatVersion = 1;
    private static readonly byte[] Magic = "VBCS"u8.ToArray();

    public sealed record Entry(SetKey Key, DateOnly Day, ulong[] Codes);

    public static string Encrypt(byte[] key, string month, long version, IReadOnlyList<Entry> entries)
    {
        var payload = Serialize(entries);
        var plain = new byte[RoundUp(4 + payload.Length)];
        BinaryPrimitives.WriteInt32LittleEndian(plain.AsSpan(0, 4), payload.Length);
        payload.CopyTo(plain, 4);

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var tag = new byte[TagSize];
        var cipher = new byte[plain.Length];
        using (var aes = new AesGcm(key, TagSize))
            aes.Encrypt(nonce, plain, cipher, tag, Aad(month, version));

        var output = new byte[NonceSize + TagSize + cipher.Length];
        nonce.CopyTo(output, 0);
        tag.CopyTo(output, NonceSize);
        cipher.CopyTo(output, NonceSize + TagSize);
        return Convert.ToBase64String(output);
    }

    public static List<Entry> Decrypt(byte[] key, string month, long version, string blobB64)
    {
        try
        {
            var data = Convert.FromBase64String(blobB64);
            if (data.Length < NonceSize + TagSize + 4) throw new CountStoreBlobException("blob kısa");

            var plain = new byte[data.Length - NonceSize - TagSize];
            using (var aes = new AesGcm(key, TagSize))
                aes.Decrypt(data.AsSpan(0, NonceSize), data.AsSpan(NonceSize + TagSize),
                            data.AsSpan(NonceSize, TagSize), plain, Aad(month, version));

            var length = BinaryPrimitives.ReadInt32LittleEndian(plain.AsSpan(0, 4));
            if (length < 0 || length > plain.Length - 4) throw new CountStoreBlobException("uzunluk geçersiz");
            return Deserialize(plain.AsSpan(4, length).ToArray());
        }
        catch (CountStoreBlobException) { throw; }
        catch (Exception ex) { throw new CountStoreBlobException($"blob açılamadı ({ex.GetType().Name})", ex); }
    }

    private static byte[] Aad(string month, long version)
        => Encoding.UTF8.GetBytes($"vb-count-store|{month}|{version}");

    private static int RoundUp(int n) => (n + PadBlock - 1) / PadBlock * PadBlock;

    private static byte[] Serialize(IReadOnlyList<Entry> entries)
    {
        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            w.Write(Magic);
            w.Write(FormatVersion);
            w.Write(entries.Count);
            foreach (var e in entries)
            {
                w.Write(e.Key.Family);
                w.Write(e.Key.PartnerId is not null);
                if (e.Key.PartnerId is not null) w.Write(e.Key.PartnerId);
                w.Write(e.Day.DayNumber);
                w.Write(e.Codes.Length);
                foreach (var c in e.Codes) w.Write(c);
            }
        }
        return ms.ToArray();
    }

    private static List<Entry> Deserialize(byte[] payload)
    {
        using var r = new BinaryReader(new MemoryStream(payload), Encoding.UTF8);
        if (!r.ReadBytes(Magic.Length).AsSpan().SequenceEqual(Magic)) throw new CountStoreBlobException("magic yanlış");
        if (r.ReadByte() != FormatVersion) throw new CountStoreBlobException("biçim sürümü bilinmiyor");

        var count = r.ReadInt32();
        var list = new List<Entry>(count);
        for (var i = 0; i < count; i++)
        {
            var family = r.ReadString();
            if (!CountFamilies.All.Contains(family)) throw new CountStoreBlobException("aile bilinmiyor");
            string? partner = r.ReadBoolean() ? r.ReadString() : null;
            var day = DateOnly.FromDayNumber(r.ReadInt32());
            var n = r.ReadInt32();
            var codes = new ulong[n];
            for (var j = 0; j < n; j++) codes[j] = r.ReadUInt64();
            list.Add(new Entry(new SetKey(family, partner), day, codes));
        }
        return list;
    }
}
