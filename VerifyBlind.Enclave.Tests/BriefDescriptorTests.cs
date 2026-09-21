using System;
using VerifyBlind.Enclave.Services.Vision;
using Xunit;

namespace VerifyBlind.Enclave.Tests
{
    /// <summary>
    /// rBRIEF tanımlayıcısının sentetik doğrulaması.
    ///
    /// <para>Buradaki asıl sınav DÖNME DEĞİŞMEZLİĞİ. Kullanıcı telefonu doğal olarak eğiyor;
    /// tanımlayıcı eğimle birlikte değişirse aynı arka plan deseni iki karede eşleşmez, ORB
    /// hiçbir şey bulamaz ve B oranı hesaplanamaz. Sessizce çöken bir hattır, bu yüzden hem
    /// tam (90°) hem ara açıda (45°, ara değerli) ayrı ayrı sabitleniyor.</para>
    /// </summary>
    public class BriefDescriptorTests
    {
        private const int N = 81;              // tek sayı: merkez tam ortada
        private const int C = N / 2;

        /// <summary>
        /// Yumuşak ve zengin sentetik doku. Beyaz gürültü KULLANILMIYOR: 5×5 yumuşatma onu
        /// griye çevirir, karşılaştırmalar yazı-tura olur ve test kendi kurduğu gürültüyü ölçer.
        /// </summary>
        private static byte[] Texture(int n, double phase = 0)
        {
            var img = new byte[n * n];
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    double v = 128
                        + 60 * Math.Sin((x + phase) / 7.0)
                        + 50 * Math.Cos((y + phase) / 5.0)
                        + 40 * Math.Sin((x + y + phase) / 11.0);
                    img[y * n + x] = (byte)Math.Clamp(v, 0, 255);
                }
            return img;
        }

        /// <summary>Saat yönünde 90° — piksel kaymasız, ara değer yok.</summary>
        private static byte[] Rotate90(byte[] src, int n)
        {
            var dst = new byte[n * n];
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                    dst[y * n + x] = src[(n - 1 - x) * n + y];
            return dst;
        }

        /// <summary>Merkez etrafında serbest açıyla döndürme (iki doğrusal ara değer).</summary>
        private static byte[] Rotate(byte[] src, int n, double angle)
        {
            var dst = new byte[n * n];
            double cos = Math.Cos(angle), sin = Math.Sin(angle);
            int c = n / 2;

            for (int y = 0; y < n; y++)
            {
                for (int x = 0; x < n; x++)
                {
                    double ddx = x - c, ddy = y - c;
                    double sx = c + ddx * cos + ddy * sin;
                    double sy = c - ddx * sin + ddy * cos;

                    int x0 = (int)Math.Floor(sx), y0 = (int)Math.Floor(sy);
                    if (x0 < 0 || y0 < 0 || x0 + 1 >= n || y0 + 1 >= n) continue;

                    double fx = sx - x0, fy = sy - y0;
                    double top = src[y0 * n + x0] * (1 - fx) + src[y0 * n + x0 + 1] * fx;
                    double bot = src[(y0 + 1) * n + x0] * (1 - fx) + src[(y0 + 1) * n + x0 + 1] * fx;
                    dst[y * n + x] = (byte)Math.Clamp(top * (1 - fy) + bot * fy, 0, 255);
                }
            }
            return dst;
        }

        private static byte[] DescribeCenter(byte[] img, double angle)
        {
            var d = BriefDescriptor.Describe(img, N, N, new KeyPoint(C, C, 100, angle));
            Assert.NotNull(d);
            return d!;
        }

        // ── Belirlenirlik ─────────────────────────────────────────────────────

        /// <summary>
        /// Desen sabit tohumlu ve tam sayı aritmetiğiyle üretiliyor. Bu bozulursa aynı kaynak
        /// farklı tanımlayıcı üretir ve "aynı kaynak → aynı PCR0" iddiası zedelenir.
        /// </summary>
        [Fact]
        public void DesenSinirlarIcindeVeYozlasmamis()
        {
            var p = BriefDescriptor.Pattern;
            Assert.Equal(256 * 4, p.Length);

            for (int i = 0; i < 256; i++)
            {
                int b = i * 4;
                Assert.InRange(p[b], -12, 12);
                Assert.InRange(p[b + 1], -12, 12);
                Assert.InRange(p[b + 2], -12, 12);
                Assert.InRange(p[b + 3], -12, 12);
                Assert.False(p[b] == p[b + 2] && p[b + 1] == p[b + 3], $"{i}. test kendini kıyaslıyor");
            }
        }

        [Fact]
        public void AyniGirdiAyniTanimlayici()
        {
            var img = Texture(N);
            Assert.Equal(DescribeCenter(img, 0.3), DescribeCenter(img, 0.3));
        }

        [Fact]
        public void KenaraYakinNoktaTanimlanmaz()
        {
            var img = Texture(N);
            Assert.Null(BriefDescriptor.Describe(img, N, N, new KeyPoint(3, C, 100, 0)));
            Assert.Null(BriefDescriptor.Describe(img, N, N, new KeyPoint(C, N - 4, 100, 0)));
        }

        // ── Ayırt etme ────────────────────────────────────────────────────────

        [Fact]
        public void AyniYamaSifirUzaklik()
        {
            var img = Texture(N);
            Assert.Equal(0, BriefDescriptor.Hamming(DescribeCenter(img, 0), DescribeCenter(img, 0)));
        }

        // ── Dönme değişmezliği — bu sınıfın varlık sebebi ──────────────────────

        /// <summary>
        /// 90°'de ara değer yok: örnekleme noktaları tam olarak aynı sahne piksellerine düşmeli.
        /// Sıfırdan sapma, yönlendirme cebirinin (dönme matrisinin işareti) yanlış olduğunu söyler.
        /// </summary>
        [Fact]
        public void DoksanDerecedeTanimlayiciDegismez()
        {
            var img = Texture(N);
            var rotated = Rotate90(img, N);

            int d = BriefDescriptor.Hamming(
                DescribeCenter(img, 0),
                DescribeCenter(rotated, Math.PI / 2));

            Assert.True(d <= 4, $"90° dönmede {d} bit kaydı — yönlendirme cebiri hatalı");
        }

        /// <summary>
        /// Gerçek durum: açı 90'ın katı değil, ara değer bulanıklığı var. Burada beklenen sıfır
        /// değil, "eşleştirmeye yetecek kadar yakın".
        /// </summary>
        [Theory]
        [InlineData(30.0)]
        [InlineData(45.0)]
        [InlineData(-60.0)]
        public void AraAcilardaTanimlayiciYakinKalir(double derece)
        {
            double angle = derece * Math.PI / 180.0;
            var img = Texture(N);
            var rotated = Rotate(img, N, angle);

            int same = BriefDescriptor.Hamming(DescribeCenter(img, 0), DescribeCenter(rotated, angle));
            int other = BriefDescriptor.Hamming(DescribeCenter(img, 0), DescribeCenter(Texture(N, 37), 0));

            Assert.True(same < 80, $"{derece}°: dönmüş eşleşme {same} bit uzakta, fazla");
            Assert.True(same < other - 20,
                $"{derece}°: dönmüş eşleşme ({same}) ilgisiz yamadan ({other}) yeterince ayrışmıyor");
        }

        /// <summary>
        /// Yönlendirme KAPALIYKEN aynı dönme tanımlayıcıyı bozmalı. Bu test olmadan, yukarıdaki
        /// testler "desen zaten dönmeye duyarsızmış" diye de geçebilirdi — yani asıl özelliği
        /// ölçtüğümüzü kanıtlayan kontrol budur.
        /// </summary>
        [Fact]
        public void YonlendirmeOlmadanDonmeTanimlayiciyiBozar()
        {
            var img = Texture(N);
            var rotated = Rotate90(img, N);

            int steered = BriefDescriptor.Hamming(
                DescribeCenter(img, 0), DescribeCenter(rotated, Math.PI / 2));
            int unsteered = BriefDescriptor.Hamming(
                DescribeCenter(img, 0), DescribeCenter(rotated, 0));

            Assert.True(unsteered > steered + 40,
                $"yönlendirmesiz {unsteered}, yönlendirmeli {steered} — fark yok, desen dönmeye zaten duyarsız");
        }
    }
}
