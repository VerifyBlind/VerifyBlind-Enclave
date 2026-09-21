using System;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>Çözülmüş gri tonlamalı görüntü.</summary>
    public readonly record struct GrayImage(byte[] Pixels, int Width, int Height);

    /// <summary>
    /// JPEG → gri tonlama. ORB piksellerle çalışır; biyometrik hat ise renkli görüntüyü kendi
    /// içinde çözüp atar, dışarıya vermez.
    ///
    /// <para>Ayrı bir sınıf olmasının sebebi <see cref="IBiometricService"/>'i şişirmemek:
    /// o arayüz kimlik ve canlılık içindir, genel görüntü işleme için değil.</para>
    /// </summary>
    public static class GrayDecoder
    {
        /// <summary>
        /// Çözer; bozuk görüntüde FIRLATMAZ, null döner. Bu bir ÖLÇÜM yolu — tek bir kötü kare
        /// yüzünden kaydı düşürmek meşru kullanıcıyı cezalandırmak olurdu.
        /// </summary>
        public static GrayImage? Decode(byte[] bytes)
        {
            try
            {
                using var image = Image.Load<L8>(bytes);
                var pixels = new byte[image.Width * image.Height];

                image.ProcessPixelRows(accessor =>
                {
                    for (int y = 0; y < accessor.Height; y++)
                    {
                        var row = accessor.GetRowSpan(y);
                        for (int x = 0; x < row.Length; x++)
                            pixels[y * accessor.Width + x] = row[x].PackedValue;
                    }
                });

                return new GrayImage(pixels, image.Width, image.Height);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Parallax] Kare çözülemedi: {ex.GetType().Name}");
                return null;
            }
        }
    }
}
