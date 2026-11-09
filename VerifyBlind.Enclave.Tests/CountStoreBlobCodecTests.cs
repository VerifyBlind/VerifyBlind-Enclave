using System.Security.Cryptography;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.UniqueCount;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

public class CountStoreBlobCodecTests
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    private static readonly DateOnly Day = new(2026, 11, 10);

    private static List<CountStoreBlobCodec.Entry> Sample() => new()
    {
        new(new SetKey(CountFamilies.PersonLogin, null), Day, new ulong[] { 1, 2, 3 }),
        new(new SetKey(CountFamilies.PartnerPerson, "aaaa-1111"), Day, new ulong[] { 42 }),
    };

    [Fact]
    public void RoundTrip_PreservesEntries()
    {
        var blob = CountStoreBlobCodec.Encrypt(Key, "2026-11", 3, Sample());
        var back = CountStoreBlobCodec.Decrypt(Key, "2026-11", 3, blob);

        Assert.Equal(2, back.Count);
        Assert.Equal(new SetKey(CountFamilies.PersonLogin, null), back[0].Key);
        Assert.Equal(Day, back[0].Day);
        Assert.Equal(new ulong[] { 1, 2, 3 }, back[0].Codes);
        Assert.Equal("aaaa-1111", back[1].Key.PartnerId);
        Assert.Equal(new ulong[] { 42 }, back[1].Codes);
    }

    [Fact]
    public void RoundTrip_EmptyMonth()
    {
        var blob = CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, new List<CountStoreBlobCodec.Entry>());
        Assert.Empty(CountStoreBlobCodec.Decrypt(Key, "2026-11", 1, blob));
    }

    [Fact]
    public void SameContent_EncryptsDifferentlyEachTime()
    {
        var a = CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample());
        var b = CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample());
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Size_IsPaddedToBlock_AndDoesNotGrowWithOneMoreCode()
    {
        var small = Convert.FromBase64String(CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample()));
        var more = Sample();
        more.Add(new(new SetKey(CountFamilies.Card, null), Day, new ulong[] { 7 }));
        var bigger = Convert.FromBase64String(CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, more));

        Assert.Equal(0, (small.Length - 28) % CountStoreBlobCodec.PadBlock);
        Assert.Equal(small.Length, bigger.Length);
    }

    [Fact]
    public void WrongMonth_Rejected()
    {
        var blob = CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample());
        Assert.Throws<CountStoreBlobException>(() => CountStoreBlobCodec.Decrypt(Key, "2026-10", 1, blob));
    }

    [Fact]
    public void WrongVersion_Rejected()
    {
        var blob = CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample());
        Assert.Throws<CountStoreBlobException>(() => CountStoreBlobCodec.Decrypt(Key, "2026-11", 2, blob));
    }

    [Fact]
    public void WrongKey_Rejected()
    {
        var blob = CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample());
        Assert.Throws<CountStoreBlobException>(() =>
            CountStoreBlobCodec.Decrypt(RandomNumberGenerator.GetBytes(32), "2026-11", 1, blob));
    }

    [Fact]
    public void TamperedByte_Rejected()
    {
        var bytes = Convert.FromBase64String(CountStoreBlobCodec.Encrypt(Key, "2026-11", 1, Sample()));
        bytes[40] ^= 0x01;
        Assert.Throws<CountStoreBlobException>(() =>
            CountStoreBlobCodec.Decrypt(Key, "2026-11", 1, Convert.ToBase64String(bytes)));
    }

    [Fact]
    public void NotBase64_Rejected()
    {
        Assert.Throws<CountStoreBlobException>(() => CountStoreBlobCodec.Decrypt(Key, "2026-11", 1, "%%%"));
    }
}
