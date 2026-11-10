using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.UniqueCount;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class UniqueCountStoreTests
{
    private static readonly string A = UniqueCountCodesTests.Tckn;
    private static readonly string B = UniqueCountCodesTests.MakeTckn("200000003");
    private const string P1 = "aaaa-1111";
    private const string P2 = "bbbb-2222";

    // 2026-11-10 09:00 UTC = 12:00 TR
    private DateTime _now = new(2026, 11, 10, 9, 0, 0, DateTimeKind.Utc);
    private static readonly DateOnly D = new(2026, 11, 10);

    private async Task<UniqueCountStore> NewStoreAsync(bool loaded = true)
    {
        var store = new UniqueCountStore(await UniqueCountCodesTests.DevHmacAsync(), () => _now);
        if (loaded) store.Load(Array.Empty<CountStoreBlob>());
        return store;
    }

    private void NextDay() => _now = _now.AddDays(1);

    private static string Code(Action a)
    {
        var ex = Assert.Throws<CountQueryException>(a);
        return ex.ErrorCode;
    }

    [Fact]
    public async Task Query_BeforeLoad_Refused()
    {
        var store = await NewStoreAsync(loaded: false);
        NextDay();
        Assert.Equal("ERR_COUNT_NOT_LOADED", Code(() => store.Query(CountFamilies.PersonLogin, null, D, D)));
    }

    [Fact]
    public async Task Save_BeforeLoad_ReturnsNotLoaded()
    {
        var store = await NewStoreAsync(loaded: false);
        var resp = store.Save();
        Assert.Equal(CountStoreSaveResponse.StatusNotLoaded, resp.Status);
        Assert.Empty(resp.Blobs);
    }

    [Fact]
    public async Task Query_Today_Refused()
    {
        var store = await NewStoreAsync();
        store.RecordLogin(A, P1);
        Assert.Equal("ERR_COUNT_DAY_NOT_CLOSED", Code(() => store.Query(CountFamilies.PersonLogin, null, D, D)));
        Assert.Equal("ERR_COUNT_DAY_NOT_CLOSED", Code(() => store.Daily(D)));
    }

    [Fact]
    public async Task SamePersonTwice_CountsOnce_AcrossDays()
    {
        var store = await NewStoreAsync();
        store.RecordLogin(A, P1);
        store.RecordLogin(A, P1);
        NextDay();
        store.RecordLogin(A, P1);
        NextDay();

        Assert.Equal(1, store.Query(CountFamilies.PersonLogin, null, D, D.AddDays(1)));
        Assert.Equal(1, store.Query(CountFamilies.PartnerPerson, P1, D, D.AddDays(1)));
        Assert.Equal(1, store.Daily(D).Single(t => t.Family == CountFamilies.PersonLogin).DistinctCount);
    }

    [Fact]
    public async Task TwoPartners_CountedPerPartner_PersonOnceGlobally()
    {
        var store = await NewStoreAsync();
        store.RecordLogin(A, P1);
        store.RecordLogin(A, P2);
        store.RecordLogin(B, P1);
        NextDay();

        Assert.Equal(2, store.Query(CountFamilies.PersonLogin, null, D, D));
        Assert.Equal(2, store.Query(CountFamilies.PartnerPerson, P1, D, D));
        Assert.Equal(1, store.Query(CountFamilies.PartnerPerson, "BBBB-2222", D, D));
        var daily = store.Daily(D);
        Assert.Equal(2, daily.Single(t => t.Family == CountFamilies.PartnerPerson && t.PartnerId == P1).DistinctCount);
    }

    [Fact]
    public async Task InvalidOrDemoTckn_NotCounted()
    {
        var store = await NewStoreAsync();
        store.RecordLogin("12345", P1);
        store.RecordLogin(EnclaveService.DemoTckn, P1);
        store.RecordLogin(A, "");
        NextDay();
        Assert.Equal(0, store.Query(CountFamilies.PersonLogin, null, D, D));
    }

    [Fact]
    public async Task Register_CountsCardAndPerson_CardOnlyWithoutValidTckn()
    {
        var store = await NewStoreAsync();
        store.RecordRegister(A, "sod-1");
        store.RecordRegister(A, "sod-2");      // aynı kişi, ikinci kart
        store.RecordRegister("", "sod-3");     // TCKN'siz → yalnız kart
        NextDay();

        Assert.Equal(3, store.Query(CountFamilies.Card, null, D, D));
        Assert.Equal(1, store.Query(CountFamilies.PersonRegister, null, D, D));
        Assert.Equal(0, store.Query(CountFamilies.PersonLogin, null, D, D));
    }

    [Fact]
    public async Task InvalidQueries_Refused()
    {
        var store = await NewStoreAsync();
        NextDay();
        Assert.Equal("ERR_COUNT_FAMILY_INVALID", Code(() => store.Query("nope", null, D, D)));
        Assert.Equal("ERR_COUNT_PARTNER_INVALID", Code(() => store.Query(CountFamilies.PartnerPerson, null, D, D)));
        Assert.Equal("ERR_COUNT_PARTNER_INVALID", Code(() => store.Query(CountFamilies.PersonLogin, P1, D, D)));
        Assert.Equal("ERR_COUNT_RANGE_INVALID", Code(() => store.Query(CountFamilies.PersonLogin, null, D, D.AddDays(-1))));
    }

    [Fact]
    public async Task SaveThenLoadIntoNewStore_KeepsCounts_AndMergesPreLoadRecords()
    {
        var hmac = await UniqueCountCodesTests.DevHmacAsync();
        var first = new UniqueCountStore(hmac, () => _now);
        first.Load(Array.Empty<CountStoreBlob>());
        first.RecordLogin(A, P1);
        var saved = first.Save();

        // Enclave yeniden başladı: yükleme gelmeden önce yeni bir kişi doğruladı.
        var second = new UniqueCountStore(hmac, () => _now);
        second.RecordLogin(B, P1);
        Assert.Equal(CountStoreSaveResponse.StatusNotLoaded, second.Save().Status);
        second.Load(saved.Blobs);
        NextDay();

        Assert.Equal(2, second.Query(CountFamilies.PersonLogin, null, D, D));
    }

    [Fact]
    public async Task Save_AlwaysReturnsCurrentMonth_AndIncrementsVersion()
    {
        var store = await NewStoreAsync();
        var first = store.Save().Blobs;
        var v1 = first.Single(b => b.Month == "2026-11");
        var v2 = store.Save().Blobs.Single(b => b.Month == "2026-11");
        Assert.Equal(new[] { "2026-10", "2026-11" }, first.Select(b => b.Month).ToList());
        Assert.Equal(1, v1.Version);
        Assert.Equal(2, v2.Version);
    }

    [Fact]
    public async Task Load_TakesHigherVersion()
    {
        var hmac = await UniqueCountCodesTests.DevHmacAsync();
        var a = new UniqueCountStore(hmac, () => _now);
        a.Load(Array.Empty<CountStoreBlob>());
        CountStoreBlob blob = a.Save().Blobs.Single(x => x.Month == "2026-11");
        for (var i = 0; i < 4; i++) blob = a.Save().Blobs.Single(x => x.Month == "2026-11");   // sürüm 5

        var b = new UniqueCountStore(hmac, () => _now);
        b.Load(new[] { blob });
        Assert.Equal(6, b.Save().Blobs.Single(x => x.Month == "2026-11").Version);
    }

    [Fact]
    public async Task Save_IncludesPreviousMonth_WhenItChangedBeforeMidnight()
    {
        _now = new DateTime(2026, 10, 31, 20, 30, 0, DateTimeKind.Utc);   // TR 23:30
        var store = await NewStoreAsync();
        store.RecordLogin(A, P1);
        _now = new DateTime(2026, 11, 1, 0, 30, 0, DateTimeKind.Utc);     // TR 03:30
        var months = store.Save().Blobs.Select(b => b.Month).ToList();
        Assert.Equal(new[] { "2026-10", "2026-11" }, months);
    }

    [Fact]
    public async Task Save_DropsDaysOlderThanTenYears()
    {
        var store = await NewStoreAsync();
        store.RecordLogin(A, P1);
        _now = _now.AddYears(10).AddDays(2);
        store.Save();
        Assert.Equal(0, store.Query(CountFamilies.PersonLogin, null, D, D));
    }

    [Fact]
    public async Task Load_TamperedBlob_ThrowsAndStaysUnloaded()
    {
        var hmac = await UniqueCountCodesTests.DevHmacAsync();
        var a = new UniqueCountStore(hmac, () => _now);
        a.Load(Array.Empty<CountStoreBlob>());
        var blob = a.Save().Blobs.Single(x => x.Month == "2026-11");
        var bytes = Convert.FromBase64String(blob.Blob);
        bytes[40] ^= 0x01;

        var b = new UniqueCountStore(hmac, () => _now);
        Assert.Throws<CountStoreBlobException>(() =>
            b.Load(new[] { new CountStoreBlob { Month = blob.Month, Version = blob.Version, Blob = Convert.ToBase64String(bytes) } }));
        Assert.False(b.IsLoaded);
    }
}
