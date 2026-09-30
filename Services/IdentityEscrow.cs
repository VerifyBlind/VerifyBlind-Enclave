using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Kimlik-HMAC sırrının (user_id / nsbd_id / doc_id / person_id / card_id türetmesi) ÇEVRİMDIŞI
/// kurtarma kopyası.
///
/// <para><b>Neden:</b> sır yalnız KMS ile sarılı durur ve yalnız attested enclave açabilir. AWS hesabı
/// kaybolursa (kapanma, askıya alınma, kök hesabın ele geçirilmesi) sır da kaybolur ve partnerlerin
/// sakladığı bütün user_id'ler kalıcı olarak değişir. Bu dosya o tek senaryoya karşıdır.</para>
///
/// <para><b>Nasıl:</b> sır, kurucunun çevrimdışı tuttuğu RSA anahtarının AÇIK yarısıyla
/// (RSA-OAEP-SHA256) şifrelenip dışarı verilir. Açık anahtar enclave imajına gömülüdür
/// (<c>Certificates/Escrow/identity-escrow-recipient.pem</c>) → PCR0'ın kapsamındadır; relay ya da
/// sunucu onu başka bir anahtarla DEĞİŞTİREMEZ. Özel yarı hiçbir sunucuda yoktur.</para>
///
/// <para><b>Bedeli:</b> kurtarma dosyası + kurucunun özel anahtarı + parolası birlikte ele geçerse,
/// herhangi bir TCKN için user_id hesaplanabilir. Bu yüzden özel anahtar çevrimdışı ve parolasından
/// ayrı saklanır. Bilet MAC sırrı bilinçli olarak YEDEKLENMEZ: onun kaybı yalnız kartların yeniden
/// eklenmesini gerektirir, kopyası ise sahte bilet üretmeye izin verirdi.</para>
/// </summary>
public static class IdentityEscrow
{
    /// <summary>İmajdaki kurtarma açık anahtarının yolu (Certificates altında, imaja kopyalanır).</summary>
    public static readonly string[] RecipientRelativePath = { "Certificates", "Escrow", "identity-escrow-recipient.pem" };

    /// <summary>Kabul edilen en küçük anahtar boyu. 4096 önerilir; 3072 altı reddedilir.</summary>
    public const int MinRecipientKeyBits = 3072;

    /// <summary>
    /// Sırrın parmak izi etiketi. Parmak izi = hex(HMAC-SHA256(sır, etiket)). Sırrı açığa çıkarmaz;
    /// kurtarma betiği dosyayı açınca aynı hesabı yapıp kopyanın doğru sır olduğunu doğrular.
    /// Aynı uç sonradan tekrar çağrılırsa canlı sırrın hâlâ aynı olduğu da görülür.
    /// </summary>
    public const string FingerprintLabel = "vb-idhmac-escrow-check-v1";

    public static string Fingerprint(byte[] secret)
    {
        using var hmac = new HMACSHA256(secret);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(FingerprintLabel))).ToLowerInvariant();
    }

    /// <summary>
    /// Kurtarma açık anahtarını imajdan yükler. Dosya yoksa <see cref="EscrowNotConfiguredException"/>;
    /// anahtar RSA değilse ya da <see cref="MinRecipientKeyBits"/>'ten küçükse reddeder.
    /// </summary>
    public static (RSA Key, string SpkiSha256Hex) LoadRecipient(string? baseDirectory = null)
    {
        var baseDir = baseDirectory ?? AppDomain.CurrentDomain.BaseDirectory;
        var path = Path.Combine(new[] { baseDir }.Concat(RecipientRelativePath).ToArray());
        if (!File.Exists(path))
            throw new EscrowNotConfiguredException(
                "Kurtarma açık anahtarı imajda yok (Certificates/Escrow/identity-escrow-recipient.pem).");

        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            rsa.Dispose();
            throw new InvalidOperationException("Kurtarma açık anahtarı okunamadı (SPKI PEM bekleniyordu).", ex);
        }

        if (rsa.KeySize < MinRecipientKeyBits)
        {
            var bits = rsa.KeySize;
            rsa.Dispose();
            throw new InvalidOperationException($"Kurtarma anahtarı çok kısa ({bits} bit, en az {MinRecipientKeyBits}).");
        }

        var spkiHash = Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        return (rsa, spkiHash);
    }
}

/// <summary>Enclave imajında kurtarma açık anahtarı yok — uç 503 döner.</summary>
public sealed class EscrowNotConfiguredException : Exception
{
    public EscrowNotConfiguredException(string message) : base(message) { }
}

/// <summary>Kurtarma dosyasının içeriği (JSON). Sır yalnız <see cref="Ciphertext"/> içinde, şifreli.</summary>
public sealed class IdentityEscrowFile
{
    [JsonPropertyName("format")] public string Format { get; init; } = "verifyblind-identity-escrow";
    [JsonPropertyName("version")] public int Version { get; init; } = 1;
    [JsonPropertyName("purpose")] public string Purpose { get; init; } = "identity-hmac";
    [JsonPropertyName("algorithm")] public string Algorithm { get; init; } = "RSA-OAEP-SHA256";
    /// <summary>Şifrelemede kullanılan açık anahtarın SPKI SHA-256'sı — kurucu kendi anahtarı mı diye bakar.</summary>
    [JsonPropertyName("recipient_key_sha256")] public string RecipientKeySha256 { get; init; } = "";
    /// <summary><see cref="IdentityEscrow.Fingerprint"/> — dosya açılınca aynısı çıkmalı.</summary>
    [JsonPropertyName("secret_fingerprint")] public string SecretFingerprint { get; init; } = "";
    /// <summary>Base64 RSA-OAEP-SHA256; açılınca {"v":1,"purpose":"identity-hmac","label":...,"secret":"base64"}.</summary>
    [JsonPropertyName("ciphertext")] public string Ciphertext { get; init; } = "";
    [JsonPropertyName("created_at_utc")] public string CreatedAtUtc { get; init; } = "";
}
