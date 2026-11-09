using Microsoft.AspNetCore.Mvc;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.UniqueCount;

namespace VerifyBlind.Enclave.Controllers;

/// <summary>
/// Tekil sayım deposu uçları (spec 2026-11-09). Relay'in ENCLAVE_URL'i ".../api/Enclave" ile biter.
/// Dışarı yalnız sayı ve enclave'in açabildiği şifreli blob çıkar; kod listesi döndüren uç YOK.
/// </summary>
[ApiController]
[Route("api/Enclave/count-store")]
public class CountStoreController : ControllerBase
{
    private readonly UniqueCountStore _store;
    private readonly IIdentityHmacService _hmac;

    public CountStoreController(UniqueCountStore store, IIdentityHmacService hmac)
    {
        _store = store;
        _hmac = hmac;
    }

    [HttpPost("load")]
    public async Task<IActionResult> Load([FromBody] CountStoreLoadRequest request)
    {
        await _hmac.EnsureSecretLoadedAsync(request.IdentityHmacSecretWrapped);
        try
        {
            _store.Load(request.Blobs);
            return Ok(new { status = CountStoreSaveResponse.StatusOk });
        }
        catch (CountStoreBlobException ex)
        {
            Console.WriteLine($"[UniqueCount] Yükleme reddedildi: {ex.Message}");
            return BadRequest(new { error_code = "ERR_COUNT_BLOB_INVALID" });
        }
    }

    [HttpPost("save")]
    public async Task<IActionResult> Save([FromBody] CountStoreSaveRequest request)
    {
        await _hmac.EnsureSecretLoadedAsync(request.IdentityHmacSecretWrapped);
        return Ok(_store.Save());
    }

    [HttpPost("query")]
    public IActionResult Query([FromBody] CountStoreQueryRequest request)
    {
        try
        {
            return Ok(new CountStoreQueryResponse
            {
                DistinctCount = _store.Query(request.Family, request.PartnerId, request.From, request.To)
            });
        }
        catch (CountQueryException ex) { return BadRequest(new { error_code = ex.ErrorCode }); }
    }

    [HttpPost("daily")]
    public IActionResult Daily([FromBody] CountStoreDailyRequest request)
    {
        try
        {
            return Ok(new CountStoreDailyResponse { Day = request.Day, Totals = _store.Daily(request.Day) });
        }
        catch (CountQueryException ex) { return BadRequest(new { error_code = ex.ErrorCode }); }
    }
}
