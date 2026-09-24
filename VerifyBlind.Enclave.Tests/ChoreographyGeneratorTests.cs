using System;
using System.Collections.Generic;
using System.Linq;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.Stance;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Duruş + olay dizisinin KURALLARI — kullanıcı kararlarıdır, her biri bir test.
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
            var stops = c.Stops;
            string d = ChoreographyGenerator.Describe(c);

            Assert.Equal(ChoreographyGenerator.Version, c.Version);
            Assert.InRange(stops.Count, ChoreographyGenerator.MinStops, ChoreographyGenerator.MaxStops);

            // Yakın çıpa: arka plan kısıtı yakın uçta bağlıyor.
            Assert.True(stops[0].Position == StancePosition.Near, d);

            // Her mesafe en az bir kez.
            foreach (var p in new[] { StancePosition.Far, StancePosition.Mid, StancePosition.Near })
                Assert.True(stops.Any(s => s.Position == p), $"{p} yok: {d}");

            // Ardışık iki durak aynı mesafede olamaz — aralarında hareket olmalı.
            for (int i = 1; i < stops.Count; i++)
                Assert.True(stops[i].Position != stops[i - 1].Position, d);

            // Tam iki olay, iki farklı türde.
            var events = stops.Where(s => s.Event != StanceEvent.None).Select(s => s.Event).ToList();
            Assert.Equal(ChoreographyGenerator.EventCount, events.Count);
            Assert.Equal(events.Count, events.Distinct().Count());
        }
    }

    /// <summary>
    /// Çekiliş tüm kapsamayı kullanıyor mu: her olay türü, her durak sayısı ve her durakta
    /// olay görülmeli. Biri hiç çıkmıyorsa saldırganın hazırlaması gereken klip sayısı
    /// sessizce azalmış demektir.
    /// </summary>
    [Fact]
    public void CekilisKapsamayiKullanir()
    {
        var eventCounts = new Dictionary<StanceEvent, int>();
        var stopCounts = new Dictionary<int, int>();
        var eventAt = new HashSet<int>();

        foreach (var nonce in Nonces(4000))
        {
            var c = ChoreographyGenerator.FromNonce(nonce);
            stopCounts[c.Stops.Count] = stopCounts.GetValueOrDefault(c.Stops.Count) + 1;
            for (int i = 0; i < c.Stops.Count; i++)
            {
                var ev = c.Stops[i].Event;
                if (ev == StanceEvent.None) continue;
                eventCounts[ev] = eventCounts.GetValueOrDefault(ev) + 1;
                eventAt.Add(i);
            }
        }

        foreach (var ev in new[] { StanceEvent.Blink, StanceEvent.Smile, StanceEvent.MouthOpen, StanceEvent.DoubleBlink })
            Assert.True(eventCounts.GetValueOrDefault(ev) > 1000, $"{ev}: {eventCounts.GetValueOrDefault(ev)}");

        Assert.True(stopCounts.GetValueOrDefault(4) > 1000);
        Assert.True(stopCounts.GetValueOrDefault(5) > 1000);
        Assert.Equal(5, eventAt.Count);   // 0..4 her durakta olay çıkabiliyor
    }

    [Fact]
    public void BosNonceReddedilir()
    {
        Assert.ThrowsAny<ArgumentException>(() => ChoreographyGenerator.FromNonce(""));
    }
}
