using System;
using System.Collections.Generic;
using System.Linq;
using VerifyBlind.Enclave.Services.Vision;
using Xunit;

namespace VerifyBlind.Enclave.Tests
{
    /// <summary>
    /// ORB hattının UÇTAN UCA doğrulaması: bilinen bir ölçek geri bulunabiliyor mu.
    ///
    /// <para>Sahne yordamsal olarak üretiliyor — dünya koordinatlarında dağılmış diskler,
    /// istenen yakınlıkta doğrudan çiziliyor. Bir görüntüyü büyütüp ara değer üretmek yerine
    /// böyle yapmanın sebebi: ara değer bulanıklığı ölçümün kendi hatasına karışır ve testin
    /// neyi ölçtüğü belirsizleşir. Burada kare çiftleri ARASINDA hiçbir yapay bozulma yok,
    /// yalnız gerçek ölçek farkı var.</para>
    ///
    /// <para>Tekrar eden desen (sinüs, tuğla) bilerek kullanılmıyor: oran testi onları zaten
    /// reddeder ve test yanlış sebepten düşerdi.</para>
    /// </summary>
    public class BackgroundScaleEstimatorTests
    {
        private const int W = 240, H = 320;
        private static readonly Blob[] BgBlobs = MakeBlobs(0xB6_1105, 420, 200);
        private static readonly Blob[] FaceBlobs = MakeBlobs(0xFACE_01, 60, 34);

        /// <summary>
        /// Sabit tohumlu sekil kumesi. Diskler DEGIL: hepsi ayni yaricapta daireler birbirinin
        /// aynisidir ve tanimlayici onlari gercekten ayirt edemez - ilk surumde esles,melerin
        /// %84'u yanlis cikti. Farkli en-boy oranli, iki tonlu dikdortgenler her noktaya kendine
        /// ozgu bir kose imzasi verir; gercek bir odanin (kitap sirti, cerceve, priz) yaptigi da budur.
        /// </summary>
        private readonly record struct Blob(double X, double Y, double W, double H, byte V1, byte V2);

        private static Blob[] MakeBlobs(uint seed, int count, int spread)
        {
            uint s = seed;
            uint Next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }

            var blobs = new Blob[count];
            for (int i = 0; i < count; i++)
                blobs[i] = new Blob(
                    (int)(Next() % (uint)(2 * spread)) - spread,
                    (int)(Next() % (uint)(2 * spread)) - spread,
                    3 + Next() % 11,
                    3 + Next() % 11,
                    (byte)(25 + Next() % 205),
                    (byte)(25 + Next() % 205));
            return blobs;
        }

        /// <summary>
        /// Sahneyi verilen yakınlıkta çizer. Arka plan ve yüz AYRI ölçeklerle çizilebilir —
        /// gerçek yüz ile düz ekran arasındaki tek fark tam olarak budur.
        /// </summary>
        private static byte[] Render(double bgScale, double faceScale, bool withFace = true)
        {
            var img = new byte[W * H];

            // Konuma gore degisen yumusak zemin. Duz bir zemin uzerinde ayni yaricapli diskler
            // birbirinin AYNISI olur; oran testi onlari hakli olarak reddeder ve test kendi
            // kurdugu belirsizligi olcer. Gercek bir odada (kitaplik, mobilya, kapi pervazi)
            // her bolgenin kendi baglami vardir - zemin onu temsil ediyor.
            for (int y = 0; y < H; y++)
                for (int x = 0; x < W; x++)
                {
                    double wx = (x - W / 2.0) / bgScale, wy = (y - H / 2.0) / bgScale;
                    double v = 110 + 38 * Math.Sin(wx / 53.0) + 32 * Math.Cos(wy / 41.0)
                                   + 24 * Math.Sin((wx + wy) / 71.0);
                    img[y * W + x] = (byte)Math.Clamp(v, 0, 255);
                }

            void Draw(Blob[] blobs, double scale)
            {
                foreach (var b in blobs)
                {
                    double cx = W / 2.0 + b.X * scale;
                    double cy = H / 2.0 + b.Y * scale;
                    double hw = b.W * scale / 2, hh = b.H * scale / 2;

                    int x0 = (int)Math.Max(0, cx - hw), x1 = (int)Math.Min(W - 1, cx + hw);
                    int y0 = (int)Math.Max(0, cy - hh), y1 = (int)Math.Min(H - 1, cy + hh);

                    for (int y = y0; y <= y1; y++)
                        for (int x = x0; x <= x1; x++)
                            img[y * W + x] = x < cx ? b.V1 : b.V2;
                }
            }

            Draw(BgBlobs, bgScale);
            if (withFace) Draw(FaceBlobs, faceScale);
            return img;
        }

        /// <summary>Yüz kutusu, yüz disklerinin kapladığı merkez bölge.</summary>
        private static Rect FaceRect(double faceScale)
        {
            int half = (int)(40 * faceScale);
            return new Rect(W / 2 - half, H / 2 - (int)(half * 1.25), 2 * half, (int)(2.5 * half));
        }

        private static BackgroundScale? Estimate(double bgA, double faceA, double bgB, double faceB) =>
            BackgroundScaleEstimator.Estimate(
                Render(bgA, faceA), W, H, FaceRect(faceA),
                Render(bgB, faceB), W, H, FaceRect(faceB));

        // ── Ölçek geri bulunuyor mu ───────────────────────────────────────────

        [Fact]
        public void AyniKareOlcekBir()
        {
            var r = Estimate(1.0, 1.0, 1.0, 1.0);

            Assert.NotNull(r);
            Assert.InRange(r!.Value.Scale, 0.98, 1.02);
        }

        /// <summary>
        /// Hattın varlık sebebi. Bilinen bir ölçek farkı geri bulunamıyorsa B oranı da
        /// hesaplanamaz ve bütün tasarım dayanaksız kalır.
        /// </summary>
        [Theory]
        [InlineData(1.15)]
        [InlineData(1.30)]
        [InlineData(1.50)]
        public void BilinenArkaPlanOlcegiGeriBulunur(double factor)
        {
            var r = Estimate(1.0, 1.0, factor, factor);

            Assert.NotNull(r);
            double error = Math.Abs(r!.Value.Scale - factor) / factor;
            Assert.True(error < 0.04,
                $"beklenen {factor:F2}, ölçülen {r.Value.Scale:F3} (%{error * 100:F1} sapma, " +
                $"{r.Value.Inliers}/{r.Value.Matches} uyumlu)");
        }

        // ── Asıl ayrım: düz yüzey mi, gerçek yüz mü ───────────────────────────

        /// <summary>
        /// DÜZ YÜZEY: yüz ve arka plan aynı düzlemde, aynı oranda büyür. Oran 1'e çıkmalı —
        /// bu bir ölçüm değil fizik sabitidir, ekranı eğmek/kaydırmak değiştiremez.
        /// </summary>
        [Fact]
        public void DuzYuzeydeOranBireYakin()
        {
            const double zoom = 1.4;
            var bg = Estimate(1.0, 1.0, zoom, zoom);
            Assert.NotNull(bg);

            double? ratio = BackgroundScaleEstimator.ParallaxRatio(zoom, bg);

            Assert.NotNull(ratio);
            Assert.InRange(ratio!.Value, 0.96, 1.04);
        }

        /// <summary>
        /// GERÇEK YÜZ: yüz 2,0 kat büyürken arka plan yalnız 1,4 kat büyür (daha uzakta olduğu
        /// için). Oran 1,43 — sahada ölçülen 1,38-1,59 bandının içinde.
        /// </summary>
        [Fact]
        public void GercekYuzdeOranBandaDuser()
        {
            var bg = Estimate(1.0, 1.0, 1.4, 2.0);
            Assert.NotNull(bg);

            double? ratio = BackgroundScaleEstimator.ParallaxRatio(2.0, bg);

            Assert.NotNull(ratio);
            Assert.InRange(ratio!.Value, 1.30, 1.60);
        }

        // ── Sözleşmeler ───────────────────────────────────────────────────────

        /// <summary>
        /// Dokusuz arka planda ölçüm İMKÂNSIZ ve bu bir red sebebi değil. Düz duvarın önündeki
        /// meşru kullanıcı burada düşerse giriş yapamaz hâle gelir.
        /// </summary>
        [Fact]
        public void DokusuzArkaPlandaOlculemez()
        {
            var flat = new byte[W * H];
            Array.Fill(flat, (byte)120);

            Assert.Null(BackgroundScaleEstimator.Estimate(flat, W, H, null, flat, W, H, null));
        }

        [Fact]
        public void YuzBolgesindekiNoktalarKullanilmaz()
        {
            var face = FaceRect(1.0);
            var features = OrbExtractor.Extract(Render(1.0, 1.0), W, H, face);

            Assert.NotEmpty(features);
            Assert.DoesNotContain(features, f => face.Contains((int)f.X, (int)f.Y));
        }

        [Fact]
        public void OlcumBelirlenir()
        {
            var a = Estimate(1.0, 1.0, 1.3, 1.3);
            var b = Estimate(1.0, 1.0, 1.3, 1.3);

            Assert.Equal(a!.Value.Scale, b!.Value.Scale);
            Assert.Equal(a.Value.Inliers, b.Value.Inliers);
        }
    }
}
