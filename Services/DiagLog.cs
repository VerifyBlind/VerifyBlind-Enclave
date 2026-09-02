using System.Diagnostics;

namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Per-request diagnostic log collector with per-step timing.
/// Enclave service methods call Begin/Ok/Fail; controller injects entries into the response as "enclave_diag".
/// Relay reads, logs with [ENCLAVE] tag, then strips before forwarding to caller.
/// </summary>
public class DiagLog
{
    private readonly List<string> _entries = new();
    private readonly Stopwatch _requestSw = Stopwatch.StartNew();
    private readonly Dictionary<string, Stopwatch> _stepTimers = new();

    /// <summary>Starts a named timer for a step. Call before the work begins.</summary>
    public void Begin(string step)
    {
        _stepTimers[step] = Stopwatch.StartNew();
    }

    public void Ok(string step, string? detail = null)
    {
        var ms = StopAndGetMs(step);
        var timing = ms.HasValue ? $" ({ms}ms)" : "";
        _entries.Add(detail != null ? $"[OK] {step}: {detail}{timing}" : $"[OK] {step}{timing}");
    }

    public void Fail(string step, string error)
    {
        var ms = StopAndGetMs(step);
        var timing = ms.HasValue ? $" ({ms}ms)" : "";
        _entries.Add($"[FAIL] {step}: {error}{timing}");
    }

    public void Info(string message) =>
        _entries.Add($"[INFO] {message}");

    /// <summary>Total elapsed ms since DiagLog was created.</summary>
    public long TotalMs => _requestSw.ElapsedMilliseconds;

    public IReadOnlyList<string> Entries => _entries;

    private long? StopAndGetMs(string step)
    {
        if (_stepTimers.Remove(step, out var sw))
        {
            sw.Stop();
            return sw.ElapsedMilliseconds;
        }
        return null;
    }
}
