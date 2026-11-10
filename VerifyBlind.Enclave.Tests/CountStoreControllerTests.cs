using Microsoft.AspNetCore.Mvc;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Controllers;
using VerifyBlind.Enclave.Services.UniqueCount;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class CountStoreControllerTests
{
    [Fact]
    public void Load_DisablesRequestSizeLimit() =>
        Assert.NotNull(Attribute.GetCustomAttribute(typeof(CountStoreController).GetMethod(nameof(CountStoreController.Load))!, typeof(Microsoft.AspNetCore.Mvc.DisableRequestSizeLimitAttribute)));

    private static async Task<(CountStoreController Controller, UniqueCountStore Store)> BuildAsync()
    {
        var hmac = await UniqueCountCodesTests.DevHmacAsync();
        var store = new UniqueCountStore(hmac);
        return (new CountStoreController(store, hmac), store);
    }

    private static string ErrorCode(IActionResult result)
    {
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var json = System.Text.Json.JsonSerializer.Serialize(bad.Value);
        return System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("error_code").GetString()!;
    }

    [Fact]
    public async Task Save_BeforeLoad_ReturnsNotLoaded()
    {
        var (c, _) = await BuildAsync();
        var ok = Assert.IsType<OkObjectResult>(await c.Save(new CountStoreSaveRequest()));
        Assert.Equal(CountStoreSaveResponse.StatusNotLoaded, Assert.IsType<CountStoreSaveResponse>(ok.Value).Status);
    }

    [Fact]
    public async Task Load_InvalidBlob_Returns400()
    {
        var (c, store) = await BuildAsync();
        var result = await c.Load(new CountStoreLoadRequest
        {
            Blobs = { new CountStoreBlob { Month = "2026-11", Version = 1, Blob = "AAAA" } }
        });
        Assert.Equal("ERR_COUNT_BLOB_INVALID", ErrorCode(result));
        Assert.False(store.IsLoaded);
    }

    [Fact]
    public async Task Query_Today_Returns400()
    {
        var (c, store) = await BuildAsync();
        await c.Load(new CountStoreLoadRequest());
        var today = store.Today();
        var result = c.Query(new CountStoreQueryRequest { Family = CountFamilies.PersonLogin, From = today, To = today });
        Assert.Equal("ERR_COUNT_DAY_NOT_CLOSED", ErrorCode(result));
    }

    [Fact]
    public async Task Daily_Yesterday_ReturnsEmptyTotals()
    {
        var (c, store) = await BuildAsync();
        await c.Load(new CountStoreLoadRequest());
        var ok = Assert.IsType<OkObjectResult>(c.Daily(new CountStoreDailyRequest { Day = store.Today().AddDays(-1) }));
        Assert.Empty(Assert.IsType<CountStoreDailyResponse>(ok.Value).Totals);
    }
}
