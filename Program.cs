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
builder.Services.AddScoped<VerifyBlind.Enclave.Services.EnclaveService>();

// Metrik toplama servisi (Admin portal için)
builder.Services.AddSingleton<VerifyBlind.Enclave.Services.EnclaveMetricsService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<VerifyBlind.Enclave.Services.EnclaveMetricsService>());

var app = builder.Build();

app.MapControllers();

// Liveness probe — EnclaveRouter.GetInstanceHealthAsync() tarafından kullanılır
app.MapGet("/health/live", () => Results.Ok(new { status = "up" }));

// Sistem metrikleri — Admin portal /api/admin/enclave-metrics tarafından sorgulanır
app.MapGet("/metrics", (VerifyBlind.Enclave.Services.EnclaveMetricsService metrics) =>
    Results.Ok(metrics.GetSnapshot()));

app.Run();
