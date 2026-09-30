using System.Security.Cryptography;
using System.Text;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Kimlik takma adlarının (user_id / nsbd_id / doc_id / person_id / card_id) türetildiği HMAC'i
/// <b>enclave içinde</b> hesaplar.
///
/// <para><b>Neden KMS GenerateMac'ten taşındı:</b> KMS'in attestation parametresi (<c>Recipient</c>)
/// yalnız Decrypt / GenerateDataKey / GenerateDataKeyPair / GenerateRandom işlemlerinde vardır;
/// <b>MAC işlemlerinde yoktur</b>. Dolayısıyla <c>kms:GenerateMac</c> izni attestation'a
/// bağlanamıyordu ve EC2 instance-role'üne verilmek zorundaydı → sunucuya erişebilen herkes
/// elindeki bir TCKN için user_id'yi doğrudan hesaplatabiliyordu. TCKN uzayı ~10⁹ olduğu için
/// hedefli sorgu anlıktı; nsbd_id için brute-force bile gerekmiyordu (girdisi ad/soyad/doğum
/// tarihi/cinsiyet). Bu, "VerifyBlind takma adı kimliğe geri çeviremez" iddiasını çürütüyordu.</para>
///
/// <para><b>Yeni model:</b> sır boot'ta bir kez, <b>attestation koşullu Decrypt</b> ile açılır
/// (wrapping CMK key policy'si PCR0 şartı taşır) ve enclave RAM'inde kalır. HMAC burada hesaplanır.
/// <c>kms:GenerateMac</c> izni instance-role'den kaldırılır → sorulacak bir yer kalmaz.
/// Desen <see cref="TicketMacService"/> ile birebir aynıdır; ayrımı EncryptionContext sağlar
/// (<c>purpose=identity-hmac</c> ≠ <c>purpose=ticket-mac</c>) — KMS bunu AAD olarak bağladığı için
/// bir blob diğerinin bağlamıyla açılamaz.</para>
///
/// <para><b>Çıktı biçimi ticket-MAC'ten farklıdır ve KORUNMALIDIR:</b> base64(HMAC-SHA256) —
/// eski <c>IKmsService.ComputeHmacAsync</c> ile aynı. Çağıranların bir kısmı sonucu doğrudan
/// kullanır (user_id), bir kısmı <c>hex(SHA256(base64'ten çözülmüş bayt))</c> sarmalar
/// (person_id / card_id / nsbd_id / doc_id). Biçim değişirse her iki yol da bozulur.</para>
///
/// <para>⚠️ Bu servis devreye girdiğinde <b>tüm mevcut takma adlar değişir</b> (anahtar değişiyor).
/// Partner verisi saklanmaya başlamadan önce yapılması bunun içindir.</para>
/// </summary>
public interface IIdentityHmacService
{
    /// <summary>
    /// Kimlik-HMAC sırrını RAM'e yükler (boot başına 1 kez, idempotent + thread-safe).
    /// AWS modunda <paramref name="wrappedBlobB64"/> attestation-bound Decrypt + CMS açma ile çözülür.
    /// Dev modunda sabit dev secret kullanılır (yalnız Development ortamında).
    /// </summary>
    Task EnsureSecretLoadedAsync(string? wrappedBlobB64);

    /// <summary>base64(HMAC-SHA256(secret, label || data)) — eski KMS çıktısıyla aynı biçim.</summary>
    string ComputeHmac(string data);
}

public class IdentityHmacService : IIdentityHmacService
{
    private readonly IKmsService _kms;
    private readonly IEnclaveKeyService _keys;
    private readonly bool _awsMode;
    private readonly bool _isDevelopment;

    /// <summary>
    /// Domain separation — bu sırrın başka bir amaçla yeniden kullanılmasını engeller.
    /// <see cref="TicketMacService"/>'in "vb-ticket-v1\n" etiketiyle aynı desen.
    /// </summary>
    private static readonly byte[] Label = Encoding.UTF8.GetBytes("vb-idhmac-v1\n");

    private byte[]? _secret;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public IdentityHmacService(IKmsService kms, IEnclaveKeyService keys, IConfiguration config, IHostEnvironment env)
    {
        _kms = kms;
        _keys = keys;
        _awsMode = string.Equals(config["KMS_MODE"], "aws", StringComparison.OrdinalIgnoreCase);
        _isDevelopment = env.IsDevelopment();
    }

    public async Task EnsureSecretLoadedAsync(string? wrappedBlobB64)
    {
        if (_secret != null) return;
        await _gate.WaitAsync();
        try
        {
            if (_secret != null) return;

            if (_awsMode)
            {
                if (string.IsNullOrEmpty(wrappedBlobB64))
                    throw new InvalidOperationException(
                        "identity_hmac_secret_wrapped boş — relay system_settings'ten blob iletmedi. " +
                        "tools/identity-hmac-setup.ps1 çalıştırıldı mı?");

                var ciphertext = Convert.FromBase64String(wrappedBlobB64);
                var attDoc = _keys.GetAttestationDocumentForRecipient();
                var cms = await _kms.DecryptWithAttestationAsync(ciphertext, attDoc, KmsPurpose.IdentityHmac);
                var secret = _keys.DecryptCmsForRecipient(cms);

                if (secret == null || secret.Length < 16)
                    throw new InvalidOperationException(
                        $"Çözülen kimlik-HMAC secret beklenenden kısa ({secret?.Length ?? 0} bayt).");

                _secret = secret;
                Console.WriteLine($"[IdentityHmacService] Kimlik-HMAC secret attestation-bound Decrypt ile yüklendi ({secret.Length} bayt).");
            }
            else
            {
                // DEV: gerçek KMS/Nitro yok → sabit dev secret.
                // FAIL-CLOSED: bu secret kaynak kodda sabit; prod'da kullanılırsa takma adlar
                // herkesçe yeniden hesaplanabilir hale gelir (tam da kapattığımız açık).
                // Bu yüzden yalnızca Development ortamında kabul edilir.
                if (!_isDevelopment)
                {
                    throw new InvalidOperationException(
                        "DEV kimlik-HMAC secret yalnızca Development ortamında kullanılabilir " +
                        "(KMS_MODE=aws bekleniyordu). Fail-closed: takma adların tahmin edilebilir " +
                        "olmasını önlemek için reddedildi.");
                }

                _secret = SHA256.HashData(Encoding.UTF8.GetBytes("verifyblind-identity-hmac-dev-secret-v1"));
                Console.WriteLine("[IdentityHmacService] DEV kimlik-HMAC secret kullanılıyor (KMS_MODE!=aws, ortam=Development).");
            }
        }
        finally { _gate.Release(); }
    }

    public string ComputeHmac(string data)
    {
        var secret = _secret ?? throw new InvalidOperationException(
            "Kimlik-HMAC secret yüklenmedi (EnsureSecretLoadedAsync çağrılmadı).");

        using var hmac = new HMACSHA256(secret);
        hmac.TransformBlock(Label, 0, Label.Length, null, 0);
        var message = Encoding.UTF8.GetBytes(data);
        hmac.TransformFinalBlock(message, 0, message.Length);
        return Convert.ToBase64String(hmac.Hash!);
    }
}
