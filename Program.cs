var builder = WebApplication.CreateBuilder(args);

// Enclave için Unix Socket desteği (Lokal TCP'yi bozmadan) 
var socketPath = "/tmp/enclave.sock";
if (File.Exists(socketPath)) File.Delete(socketPath);

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    if (builder.Environment.IsDevelopment())
    {
        // Dev: Docker bridge üzerinden relay erişebilmesi için 0.0.0.0 (AnyIP) kullan
        serverOptions.ListenAnyIP(5101);
    }
    else
    {
        // Production: Yalnızca Unix socket — vsock bridge (socat) bağlanır
        // Nitro Enclave'de ağ arayüzü yok, TCP gereksiz
        serverOptions.ListenUnixSocket(socketPath);
    }
});

// Add services to the container.
builder.Services.AddControllers()
    .AddJsonOptions(options => {
        options.JsonSerializerOptions.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
    });
builder.Services.AddSingleton<VerifyBlind.Enclave.Services.INsmProvider, VerifyBlind.Enclave.Services.NsmProvider>();

// KMS_MODE: "local" (default) = LocalKmsService, "aws" = AwsKmsService
var kmsMode = builder.Configuration["KMS_MODE"] ?? "local";
var kmsEndpoint = builder.Configuration["KMS:Endpoint"] ?? "(default)";
var kmsRegion = builder.Configuration["KMS:Region"] ?? "(default)";
Console.WriteLine($"[ENCLAVE BOOT] KMS_MODE={kmsMode} | KMS.Region={kmsRegion} | KMS.Endpoint={kmsEndpoint} | ASPNETCORE_ENVIRONMENT={builder.Environment.EnvironmentName}");

builder.Services.AddSingleton<VerifyBlind.Enclave.Services.IEnclaveKeyService, VerifyBlind.Enclave.Services.EnclaveKeyService>();
if (kmsMode == "aws")
{
    Console.WriteLine("[ENCLAVE BOOT] IKmsService => AwsKmsService");
    builder.Services.AddSingleton<VerifyBlind.Enclave.Services.IKmsService, VerifyBlind.Enclave.Services.AwsKmsService>();
}
else
{
    Console.WriteLine("[ENCLAVE BOOT] IKmsService => LocalKmsService");
    builder.Services.AddSingleton<VerifyBlind.Enclave.Services.IKmsService, VerifyBlind.Enclave.Services.LocalKmsService>();
}
builder.Services.AddSingleton<VerifyBlind.Enclave.Services.IBiometricService, VerifyBlind.Enclave.Services.BiometricService>();
builder.Services.AddSingleton<VerifyBlind.Enclave.Services.IAntiSpoofService, VerifyBlind.Enclave.Services.AntiSpoofService>();
// Ticket Forgery fix: ticket'ı enclave-içi MAC ile imzala/doğrula. Singleton — secret boot başına
// 1 kez attestation-bound Decrypt ile yüklenip RAM'de cache'lenir (TICKET_FORGERY_FIX_PLAN.md).
builder.Services.AddSingleton<VerifyBlind.Enclave.Services.ITicketMacService, VerifyBlind.Enclave.Services.TicketMacService>();
builder.Services.AddScoped<VerifyBlind.Enclave.Services.EnclaveService>();

// Metrik toplama servisi (Admin portal için)
builder.Services.AddSingleton<VerifyBlind.Enclave.Services.EnclaveMetricsService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<VerifyBlind.Enclave.Services.EnclaveMetricsService>());

var app = builder.Build();

// --- Güvenlik denetimi #1: ML modelleri fail-CLOSED startup kontrolü ---
// Pasif canlılık (anti-spoof) ve biyometrik modeller yüklenemezse enclave PROD'da hiç ayağa
// kalkmamalı — aksi halde kayıtlar model-yokluğunda sessizce güvenlik-düşük çalışırdı. Bu, model
// eksikliğini istek-zamanı outage yerine deploy-zamanı arıza olarak yakalar. (İstek-zamanı
// EnforceAntiSpoof / biyometrik kontrolleri yine backstop olarak reddeder.)
if (!app.Environment.IsDevelopment())
{
    using var startupScope = app.Services.CreateScope();
    var antiSpoof = startupScope.ServiceProvider.GetRequiredService<VerifyBlind.Enclave.Services.IAntiSpoofService>();
    var biometric = startupScope.ServiceProvider.GetRequiredService<VerifyBlind.Enclave.Services.IBiometricService>();
    if (!antiSpoof.IsModelLoaded || !biometric.IsModelLoaded)
    {
        Console.WriteLine($"[ENCLAVE BOOT][FATAL] ML modelleri eksik (antiSpoof={antiSpoof.IsModelLoaded}, biometric={biometric.IsModelLoaded}). " +
                          "Güvenlik gereği enclave başlatılmıyor. minifasnet_v2.onnx / w600k_r50.onnx (Git LFS) dosyalarını kontrol edin.");
        throw new InvalidOperationException("ML modelleri yüklenemedi — enclave fail-closed başlatılmadı (güvenlik denetimi #1).");
    }
    Console.WriteLine("[ENCLAVE BOOT] ML modelleri doğrulandı (anti-spoof + biyometrik yüklü) ✓");

    // --- Güvenlik denetimi #2: DEV ticket-MAC secret'ı PROD'da fail-CLOSED ---
    // KMS_MODE != "aws" iken TicketMacService sabit bir DEV secret'a düşer
    // (SHA256("verifyblind-ticket-mac-dev-secret-v1")) — kaynak kodda olduğu için herkes
    // yeniden hesaplayabilir ve "bu pasaport doğrulandı" diyen sahte bir SignedTicket üretip
    // MRZ/passive auth/biyometri/anti-spoof'un TAMAMINI atlayabilir. Prod'da bu yola girilmesi
    // bir yapılandırma kazasıdır; sessizce güvenlik-düşük çalışmak yerine hiç başlamamalı.
    // Dev-secret yolu artık TicketMacService içinde de ayrıca reddediliyor (savunma derinliği).
    if (!string.Equals(kmsMode, "aws", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"[ENCLAVE BOOT][FATAL] KMS_MODE='{kmsMode}' (aws değil) ve ortam '{app.Environment.EnvironmentName}' " +
                          "— bu, ticket-MAC için kaynak-kodda sabit DEV secret'ı seçerdi ve ticket sahteciliğine açık kapı bırakırdı. " +
                          "Güvenlik gereği enclave başlatılmıyor. Prod'da KMS_MODE=aws olmalı.");
        throw new InvalidOperationException(
            $"KMS_MODE='{kmsMode}' non-Development ortamda kabul edilmez — enclave fail-closed başlatılmadı (güvenlik denetimi #2).");
    }
    Console.WriteLine("[ENCLAVE BOOT] KMS_MODE=aws doğrulandı (attestation-bound ticket-MAC secret) ✓");
}

app.MapControllers();

// Liveness probe — EnclaveRouter.GetInstanceHealthAsync() tarafından kullanılır
app.MapGet("/health/live", () => Results.Ok(new { status = "up" }));

// Sistem metrikleri — Admin portal /api/admin/enclave-metrics tarafından sorgulanır
app.MapGet("/metrics", (VerifyBlind.Enclave.Services.EnclaveMetricsService metrics) =>
    Results.Ok(metrics.GetSnapshot()));

app.Run();
