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
            Assert.Equal(ChoreographyGenerator.EventCount, c.Events.Count);

            // Hepsi farklı ve hiçbiri "yok".
            Assert.Equal(c.Events.Count, c.Events.Distinct().Count());
            Assert.DoesNotContain(LivenessEvent.None, c.Events);
            Assert.False(d.Contains("none"), d);
        }
    }

    /// <summary>
    /// Çekiliş tüm kapsamayı kullanıyor mu: her olay her konumda görülmeli ve 24 dizinin hepsi
    /// çıkmalı. Biri hiç çıkmıyorsa saldırganın hazırlaması gereken klip sayısı sessizce
    /// azalmış demektir.
    /// </summary>
    [Fact]
    public void CekilisKapsamayiKullanir()
    {
        var seen = new HashSet<string>();
        var atPosition = new Dictionary<(LivenessEvent, int), int>();

        foreach (var nonce in Nonces(6000))
        {
            var c = ChoreographyGenerator.FromNonce(nonce);
            seen.Add(ChoreographyGenerator.Describe(c));
            for (int i = 0; i < c.Events.Count; i++)
                atPosition[(c.Events[i], i)] = atPosition.GetValueOrDefault((c.Events[i], i)) + 1;
        }

        Assert.Equal(24, seen.Count);   // 4 × 3 × 2
        foreach (var ev in new[] { LivenessEvent.Blink, LivenessEvent.Smile, LivenessEvent.MouthOpen, LivenessEvent.DoubleBlink })
            for (int i = 0; i < ChoreographyGenerator.EventCount; i++)
                Assert.True(atPosition.GetValueOrDefault((ev, i)) > 1000, $"{ev}@{i}: {atPosition.GetValueOrDefault((ev, i))}");
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
    }
}
