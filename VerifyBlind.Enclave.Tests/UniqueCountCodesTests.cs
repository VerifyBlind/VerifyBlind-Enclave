using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Moq;
using VerifyBlind.Enclave.Services;
using VerifyBlind.Enclave.Services.UniqueCount;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>Tekil sayım kodları: mevcut takma adlarla (person_id / user_id / card_id) eşleşmemeli.</summary>
public class UniqueCountCodesTests
{
    internal const string Tckn = "10000000146";   // algoritmaya uygun: d10 = (1+1)*7 % 10 = 4, d11 = 6
    private const string Sod = "ab12cd34ef56";

    /// <summary>İlk 9 haneden geçerli TCKN üretir (resmî algoritma).</summary>
    internal static string MakeTckn(string first9)
    {
        var d = first9.Select(c => c - '0').ToArray();
        var d10 = (((d[0] + d[2] + d[4] + d[6] + d[8]) * 7) - (d[1] + d[3] + d[5] + d[7])) % 10;
        if (d10 < 0) d10 += 10;
        var d11 = (d.Sum() + d10) % 10;
        return first9 + d10 + d11;
    }

    /// <summary>Dev modu kimlik-HMAC servisi (sabit dev sırrı, yalnız Development).</summary>
    internal static async Task<IdentityHmacService> DevHmacAsync()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["KMS_MODE"] = "local" })
            .Build();
        var env = new Mock<IHostEnvironment>();
        env.Setup(e => e.EnvironmentName).Returns("Development");
        var svc = new IdentityHmacService(Mock.Of<IKmsService>(), Mock.Of<IEnclaveKeyService>(), config, env.Object);
        await svc.EnsureSecretLoadedAsync(null);
        return svc;
    }

    [Fact]
    public async Task Person_IsDeterministic()
    {
        var h = await DevHmacAsync();
        Assert.Equal(CountCodes.Person(h, Tckn), CountCodes.Person(h, Tckn));
        Assert.NotEqual(CountCodes.Person(h, Tckn), CountCodes.Person(h, MakeTckn("200000003")));
    }

    [Fact]
    public async Task Codes_DoNotMatchExistingPseudonymInputs()
    {
        var h = await DevHmacAsync();
        Assert.NotEqual(CountCodes.First8(h.ComputeHmac($"{Tckn}_Person_id")), CountCodes.Person(h, Tckn));
        Assert.NotEqual(CountCodes.First8(h.ComputeHmac($"{Tckn}:partner-1")), CountCodes.PartnerPerson(h, Tckn, "partner-1"));
        Assert.NotEqual(CountCodes.First8(h.ComputeHmac($"{Sod}_Card_id")), CountCodes.Card(h, Sod));
    }

    [Fact]
    public async Task PartnerPerson_DiffersPerPartner_AndIgnoresCase()
    {
        var h = await DevHmacAsync();
        var a = CountCodes.PartnerPerson(h, Tckn, "AAAA-1111");
        Assert.Equal(a, CountCodes.PartnerPerson(h, Tckn, "aaaa-1111"));
        Assert.NotEqual(a, CountCodes.PartnerPerson(h, Tckn, "bbbb-2222"));
        Assert.NotEqual(a, CountCodes.Person(h, Tckn));
    }

    [Fact]
    public void First8_ReadsBigEndianPrefix()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        Assert.Equal(0x0102030405060708UL, CountCodes.First8(Convert.ToBase64String(bytes)));
    }
}
