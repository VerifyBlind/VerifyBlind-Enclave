namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Attestation belgesini kendi kendine taze tutar (arka plan timer'ı).
///
/// NEDEN GEREKLİ: belge TEMBEL üretiliyordu — yalnız bir handshake geldiğinde
/// <see cref="IEnclaveKeyService.GetAttestationDocument"/> çağrılıyor ve vadesi dolmuşsa orada
/// yenileniyordu. Trafiği olmayan bir gecede hiç çağrı gelmiyor, sertifika (3 saatlik) sessizce
/// ölüyor ve sabah ilk kullanıcı uygulamayı açamıyor. 2026-08-25 ve 26'da art arda yaşandı.
///
/// ⚠️ Kök neden SAAT KAYMASI DEĞİLDİ. Ölçüldü: 14 saat sonra enclave saati relay'den yalnız
/// 0,097 saniye sapmıştı. Belge, saat yanlış olduğu için değil, KİMSE İSTEMEDİĞİ için ölüyordu.
///
/// Neden enclave'in içinde, relay'de bir cron değil: burada olması sistemi kendi kendine yeter
/// kılıyor. Relay tarafındaki bir iş, relay'in ayakta ve o işin kayıtlı olmasına bağlı olurdu —
/// yani attestation'ın canlılığı başka bir bileşenin sağlığına bağlanırdı. Enclave kendi
/// belgesinden kendisi sorumlu.
///
/// Aralık 15 dakika: sertifika 3 saat geçerli ve yenileme bitişe 30 dk kala yapılıyor. 15
/// dakikalık tik, o yenileme penceresine her koşulda birkaç kez düşer.
/// </summary>
public sealed class AttestationRefreshService : BackgroundService
{
    private readonly IEnclaveKeyService _keys;
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);

    public AttestationRefreshService(IEnclaveKeyService keys) => _keys = keys;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Console.WriteLine($"[AttestationRefresh] Başladı — her {Interval.TotalMinutes:F0} dakikada bir tazelik kontrolü.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Vadesi dolmadıysa bu çağrı önbellekten döner ve hiçbir maliyeti yoktur;
                // dolduysa NSM'den yeni belge mint edilir. Karar mantığı tek yerde kalsın diye
                // burada tarih karşılaştırması YAPILMIYOR.
                _keys.GetAttestationDocument();
            }
            catch (Exception ex)
            {
                // Yut ve devam et: bu döngünün ölmesi, tam da önlemeye çalıştığımız sessiz
                // bayatlamayı geri getirirdi.
                Console.WriteLine($"[AttestationRefresh] Tazeleme denemesi başarısız: {ex.Message}");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;   // kapanış — normal
            }
        }

        Console.WriteLine("[AttestationRefresh] Durdu.");
    }
}
