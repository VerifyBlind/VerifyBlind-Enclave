using System.Diagnostics;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Enclave içindeki CPU/RAM/uptime metriklerini 3 saniyede bir toplar.
/// Admin portal /api/admin/enclave-metrics endpoint'i tarafından sorgulanır.
/// </summary>
public class EnclaveMetricsService : BackgroundService
{
    private EnclaveMetricsSnapshot _latest = new();
    private readonly DateTime _startedAt = DateTime.UtcNow;
    private TimeSpan _lastCpuTime = TimeSpan.Zero;
    private DateTime _lastSampleAt = DateTime.UtcNow;

    public EnclaveMetricsSnapshot GetSnapshot() => _latest;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var proc = Process.GetCurrentProcess();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(3000, stoppingToken);

                proc.Refresh();
                var now = DateTime.UtcNow;
                var cpuUsed = proc.TotalProcessorTime;
                var elapsed = (now - _lastSampleAt).TotalSeconds;
                var cpuDelta = (cpuUsed - _lastCpuTime).TotalSeconds;
                var cpuPercent = elapsed > 0
                    ? Math.Round(cpuDelta / (Environment.ProcessorCount * elapsed) * 100, 1)
                    : 0;

                _lastCpuTime = cpuUsed;
                _lastSampleAt = now;

                _latest = new EnclaveMetricsSnapshot
                {
                    Timestamp     = now,
                    CpuPercent    = Math.Clamp(cpuPercent, 0, 100),
                    RamUsedMb     = Math.Round(proc.WorkingSet64 / 1024.0 / 1024.0, 1),
                    UptimeSeconds = (now - _startedAt).TotalSeconds,
                    ThreadCount   = proc.Threads.Count,
                };
            }
            catch (OperationCanceledException) { break; }
            catch { /* ignore */ }
        }
    }
}

public class EnclaveMetricsSnapshot
{
    public DateTime Timestamp     { get; set; } = DateTime.UtcNow;
    public double CpuPercent      { get; set; }
    public double RamUsedMb       { get; set; }
    public double UptimeSeconds   { get; set; }
    public int    ThreadCount     { get; set; }
}
