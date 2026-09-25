using System;
using System.Collections.Generic;
using System.Linq;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.Liveness;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Olay dizisinin KURALLARI — kullanıcı kararlarıdır, her biri bir test.
///
/// <para>Dizi nonce'tan türetildiği için belirlenimcilik bir güvenlik özelliği: register'da
/// enclave aynı nonce'tan AYNI diziyi üretemezse istemcinin gönderdiğini neye göre ölçtüğünü
/// bilemez.</para>
/// </summary>
public class ChoreographyGeneratorTests
{
    private static IEnumerable<string> Nonces(int n) =>
        Enumerable.Range(0, n).Select(i => Guid.NewGuid().ToString("N"));

    [Fact]
    public void AyniNonceAyniDiziyiUretir()
    {
        foreach (var nonce in Nonces(50))
        {
            var a = ChoreographyGenerator.Describe(ChoreographyGenerator.FromNonce(nonce));
            var b = ChoreographyGenerator.Describe(ChoreographyGenerator.FromNonce(nonce));
            Assert.Equal(a, b);
        }
    }

    /// <summary>Sabit bir nonce için sabit dizi — türetme sessizce değişirse eski el sıkışmalar kırılır.</summary>
    [Fact]
    public void TuretmeSabittir()
    {
        var first = ChoreographyGenerator.Describe(
            ChoreographyGenerator.FromNonce("00000000000000000000000000000000"));
        var again = ChoreographyGenerator.Describe(
            ChoreographyGenerator.FromNonce("00000000000000000000000000000000"));
        Assert.Equal(first, again);
        Assert.NotEqual(first, ChoreographyGenerator.Describe(
            ChoreographyGenerator.FromNonce("00000000000000000000000000000001")));
    }

    [Fact]
    public void KurallarHerDizideTutar()
    {
        foreach (var nonce in Nonces(5000))
        {
            var c = ChoreographyGenerator.FromNonce(nonce);
            string d = ChoreographyGenerator.Describe(c);

            Assert.Equal(ChoreographyGenerator.Version, c.Version);
            Assert.Equal(5, c.Events.Count);

            // Tekrar serbest ama art arda değil; hiçbiri "yok".
            for (int i = 1; i < c.Events.Count; i++)
                Assert.NotEqual(c.Events[i - 1], c.Events[i]);
            Assert.DoesNotContain(LivenessEvent.None, c.Events);
            Assert.False(d.Contains("none"), d);
        }
    }

    /// <summary>
    /// Çekiliş tüm kapsamayı kullanıyor mu: her olay her konumda görülmeli ve 324 dizinin hepsi
    /// çıkmalı. Biri hiç çıkmıyorsa saldırganın hazırlaması gereken klip sayısı sessizce
    /// azalmış demektir.
    /// </summary>
    [Fact]
    public void CekilisKapsamayiKullanir()
    {
        var seen = new HashSet<string>();
        var atPosition = new Dictionary<(LivenessEvent, int), int>();

        foreach (var nonce in Nonces(20000))
        {
            var c = ChoreographyGenerator.FromNonce(nonce);
            seen.Add(ChoreographyGenerator.Describe(c));
            for (int i = 0; i < c.Events.Count; i++)
                atPosition[(c.Events[i], i)] = atPosition.GetValueOrDefault((c.Events[i], i)) + 1;
        }

        Assert.Equal(324, seen.Count);   // 4 × 3 × 3 × 3 × 3
        foreach (var ev in new[] { LivenessEvent.Blink, LivenessEvent.Smile, LivenessEvent.MouthOpen, LivenessEvent.DoubleBlink })
            for (int i = 0; i < ChoreographyGenerator.EventCount; i++)
                Assert.True(atPosition.GetValueOrDefault((ev, i)) > 4000, $"{ev}@{i}: {atPosition.GetValueOrDefault((ev, i))}");
    }

    [Fact]
    public void GirisTekHareketIsterDuzKirpmaYok()
    {
        var seen = new Dictionary<LivenessEvent, int>();
        foreach (var nonce in Nonces(6000))
        {
            var c = ChoreographyGenerator.ForLogin(nonce);
            Assert.Equal(ChoreographyGenerator.Version, c.Version);
            var ev = Assert.Single(c.Events);
            seen[ev] = seen.GetValueOrDefault(ev) + 1;
        }
        Assert.DoesNotContain(LivenessEvent.Blink, seen.Keys);
        foreach (var ev in new[] { LivenessEvent.Smile, LivenessEvent.MouthOpen, LivenessEvent.DoubleBlink })
            Assert.True(seen.GetValueOrDefault(ev) > 1700, $"{ev}: {seen.GetValueOrDefault(ev)}");
    }

    /// <summary>
    /// 🔴 İSTEMCİLER AYNI TÜRETMEYİ YAPIYOR (login-handshake nonce'tan önce hazırlanıyor, hareketi
    /// söyleyecek bir tur yok). Bu vektörler Android <c>LoginEventTest</c> ve iOS
    /// <c>LoginEventTests</c>'te AYNEN duruyor — biri değişirse üçü birlikte değişir.
    /// </summary>
    [Theory]
    [InlineData("00000000000000000000000000000000", LivenessEvent.Smile)]
    [InlineData("b6f1c1c56d0a4b8e9d3a2f5c7e8a9b10", LivenessEvent.MouthOpen)]
    [InlineData("7c9e6679-7425-40de-944b-e07fc1f90ae7", LivenessEvent.MouthOpen)]
    [InlineData("vector-0", LivenessEvent.DoubleBlink)]
    [InlineData("A1b2-C3d4", LivenessEvent.Smile)]
    public void GirisTuretmesiSabittir(string nonce, LivenessEvent expected)
    {
        Assert.Equal(expected, Assert.Single(ChoreographyGenerator.ForLogin(nonce).Events));
    }

    [Fact]
    public void GirisVeKayitAyriAlanlardanTuretilir()
    {
        // Aynı nonce iki akışta bağımsız çekilişe gider: kayıt dizisinin ilk hareketi giriş
        // hareketini belirlemez.
        int differ = 0;
        foreach (var nonce in Nonces(3000))
            if (ChoreographyGenerator.FromNonce(nonce).Events[0] != ChoreographyGenerator.ForLogin(nonce).Events[0])
                differ++;
        Assert.InRange(differ, 1500, 3000);
    }

    [Fact]
    public void CiftKirpmaIkiKareIster()
    {
        Assert.Equal(2, ChoreographyGenerator.FramesFor(LivenessEvent.DoubleBlink));
        Assert.Equal(1, ChoreographyGenerator.FramesFor(LivenessEvent.Blink));
        Assert.Equal(1, ChoreographyGenerator.FramesFor(LivenessEvent.Smile));
        Assert.Equal(1, ChoreographyGenerator.FramesFor(LivenessEvent.MouthOpen));
    }

    [Fact]
    public void BosNonceReddedilir()
    {
        Assert.ThrowsAny<ArgumentException>(() => ChoreographyGenerator.FromNonce(""));
        Assert.ThrowsAny<ArgumentException>(() => ChoreographyGenerator.ForLogin(""));
    }
}
