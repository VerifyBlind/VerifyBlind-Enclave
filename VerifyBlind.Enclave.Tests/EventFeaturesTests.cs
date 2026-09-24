using System;
using VerifyBlind.Enclave.Services.FaceAlignment;
using VerifyBlind.Enclave.Services.Stance;
using Xunit;

namespace VerifyBlind.Enclave.Tests;

/// <summary>
/// Olay özelliklerinin YÖNÜ doğru mu: açık göz kapalı gözden yüksek kontrast verir, açık
/// ağız kapalı ağızdan çok koyu piksel verir. Eşik yok — bunlar ölçüm; test yalnız
/// ölçünün ölçmesi gereken şeye tepki verdiğini doğruluyor.
/// </summary>
public class EventFeaturesTests
{
    private const int S = FaceAligner.OutputSize;

    private static byte[] Skin(byte value = 150)
    {
        var luma = new byte[S * S];
        Array.Fill(luma, value);
        return luma;
    }

    private static void Disk(byte[] luma, double cx, double cy, double r, byte value)
    {
        for (int y = 0; y < S; y++)
            for (int x = 0; x < S; x++)
                if ((x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r)
                    luma[y * S + x] = value;
    }

    private static void Box(byte[] luma, int x0, int y0, int x1, int y1, byte value)
    {
        for (int y = y0; y < y1; y++)
            for (int x = x0; x < x1; x++)
                luma[y * S + x] = value;
    }

    /// <summary>Açık göz: beyaz sklera üstünde koyu iris. Kapalı göz: tekdüze deri.</summary>
    [Fact]
    public void AcikGozKapalidanYuksekKontrastVerir()
    {
        var dst = FaceAligner.CanonicalLandmarks;
        var open = Skin();
        foreach (int k in new[] { 0, 2 })
        {
            Box(open, (int)dst[k] - 8, (int)dst[k + 1] - 3, (int)dst[k] + 9, (int)dst[k + 1] + 4, 230);
            Disk(open, dst[k], dst[k + 1], 3.5, 30);
        }
        var closed = Skin();

        double o = EventFeatures.EyeContrast(open);
        double c = EventFeatures.EyeContrast(closed);
        Assert.True(o > 40, $"açık={o}");
        Assert.True(c < 1, $"kapalı={c}");
        // Olay ölçüsü: 1 − kapalı/açık → kapanınca 1'e yakın.
        Assert.True(1 - c / o > 0.9);
    }

    [Fact]
    public void AcikAgizKoyuPikselVerir()
    {
        var dst = FaceAligner.CanonicalLandmarks;
        var closed = Skin();
        var open = Skin();
        // Ağız köşelerinin arası, çizginin biraz altı: açık ağzın boşluğu.
        Box(open, (int)dst[6] + 5, (int)dst[7] - 3, (int)dst[8] - 5, (int)dst[7] + 10, 20);

        double c = EventFeatures.MouthDarkFraction(closed);
        double o = EventFeatures.MouthDarkFraction(open);
        Assert.Equal(0, c);
        Assert.True(o > 0.4, $"açık={o}");
    }

    /// <summary>Referans aynı karenin cildi: ışık kısılınca oran bozulmamalı.</summary>
    [Fact]
    public void AgizOlcusuIsiktanBagimsiz()
    {
        var dst = FaceAligner.CanonicalLandmarks;
        var bright = Skin(180);
        var dim = Skin(90);
        Box(bright, (int)dst[6] + 5, (int)dst[7] - 3, (int)dst[8] - 5, (int)dst[7] + 10, 30);
        Box(dim, (int)dst[6] + 5, (int)dst[7] - 3, (int)dst[8] - 5, (int)dst[7] + 10, 15);

        Assert.Equal(EventFeatures.MouthDarkFraction(bright), EventFeatures.MouthDarkFraction(dim), 3);
    }

    [Fact]
    public void AgizGenisligiHamNoktalardan()
    {
        // Gözler 60 px arayla, ağız köşeleri 48 px → 0,8. Gülümsemede köşeler açılır.
        float[] neutral = { 100, 100, 160, 100, 130, 130, 106, 160, 154, 160 };
        float[] smile = { 100, 100, 160, 100, 130, 130, 100, 158, 160, 158 };

        Assert.Equal(0.8, EventFeatures.MouthWidthRatio(neutral)!.Value, 3);
        Assert.True(EventFeatures.MouthWidthRatio(smile) > EventFeatures.MouthWidthRatio(neutral));
        Assert.Null(EventFeatures.MouthWidthRatio(new float[4]));
    }
}
