using System;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>
    /// rBRIEF TANIMLAYICI — ORB'un ikinci aşaması.
    ///
    /// <para><b>Ne yapar:</b> bir köşenin çevresindeki yamadan 256 bitlik bir imza çıkarır. Her bit
    /// tek bir karşılaştırmadır: yamada önceden belirlenmiş iki noktadan hangisi daha parlak.
    /// İki köşenin "aynı desen mi" sorusu böylece iki tam sayının XOR'una iner — Hamming uzaklığı.
    /// Ondalıklı vektör yok, karekök yok; enclave'in CPU bütçesi için önemli olan bu.</para>
    ///
    /// <para><b>Neden "r" (rotated):</b> düz BRIEF kamera eğildiğinde çöker, çünkü karşılaştırma
    /// noktaları görüntüye sabitlenmiştir. Burada noktalar köşenin KENDİ yönelimiyle döndürülerek
    /// okunuyor (<see cref="KeyPoint.Angle"/>), yani desen döndüğünde imza değişmiyor. Kullanıcı
    /// telefonu doğal olarak eğdiği için bu isteğe bağlı değil, şart.</para>
    ///
    /// <para><b>Desen nasıl seçildi:</b> ORB makalesi 256 testi eğitimle seçer (varyansı yüksek,
    /// aralarındaki bağıntı düşük olacak şekilde). Burada o eğitilmiş tablo YOK; yerine sabit
    /// tohumlu, yamaya Gauss benzeri dağılmış bir desen üretiliyor — yani klasik BRIEF deseni.
    /// Sonuç biraz daha zayıf ayırt eder ama doğrulanabilir ve eğitilmiş tabloyu sonradan
    /// koymanın önünde bir engel yok.</para>
    ///
    /// <para>🔴 <b>Desen üretimi TAMAMEN TAM SAYI aritmetiğidir.</b> Kayan noktalı bir üreteç
    /// (Box-Muller gibi) platformdan platforma son bitte oynayabilir; enclave'in bütün güven
    /// modeli "aynı kaynak → aynı PCR0" iddiasına dayandığı için burada belirsizliğe yer yok.
    /// Aynı kaynak her derlemede aynı 256 testi üretir.</para>
    /// </summary>
    public static class BriefDescriptor
    {
        /// <summary>Tanımlayıcı uzunluğu — 256 bit.</summary>
        public const int Bytes = 32;

        private const int Tests = Bytes * 8;

        /// <summary>
        /// Örnekleme noktalarının yamada kalabileceği en büyük yarıçap.
        /// <see cref="FastDetector.OrientationRadius"/> (15) eksi yumuşatma penceresi payı.
        /// </summary>
        private const int SampleRadius = 12;

        /// <summary>Örnek alınırken ortalaması alınan kutunun yarıçapı (5×5).</summary>
        private const int SmoothRadius = 2;

        /// <summary>
        /// 256 test çifti: (x1, y1, x2, y2), köşe merkezine göre.
        /// Bir kez üretilir; süreç boyunca ve derlemeler arasında aynıdır.
        /// </summary>
        internal static readonly sbyte[] Pattern = BuildPattern();

        /// <summary>
        /// Sabit tohumlu, kayan noktasız desen üretimi.
        ///
        /// <para>Merkeze yakın noktaları biraz daha sık seçmek için her koordinat DÖRT düzgün
        /// çekilişin ortalaması olarak alınıyor (merkezi limit): kutu dağılımdan daha çan benzeri
        /// bir dağılım, tamamen tam sayı işlemiyle.</para>
        /// </summary>
        private static sbyte[] BuildPattern()
        {
            var pattern = new sbyte[Tests * 4];
            uint state = 0x1D0B_C0DE;   // sabit tohum — değiştirmek TÜM tanımlayıcıları değiştirir

            uint Next()
            {
                // xorshift32: deterministik, hızlı, tam sayı.
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                return state;
            }

            sbyte Coord()
            {
                int sum = 0;
                for (int i = 0; i < 4; i++)
                    sum += (int)(Next() % (uint)(2 * SampleRadius + 1)) - SampleRadius;
                return (sbyte)(sum / 4);
            }

            for (int i = 0; i < Tests; i++)
            {
                // Aynı noktayı kendisiyle kıyaslayan test bilgi taşımaz; ayrışana kadar çek.
                sbyte x1, y1, x2, y2;
                do
                {
                    x1 = Coord(); y1 = Coord();
                    x2 = Coord(); y2 = Coord();
                } while (x1 == x2 && y1 == y2);

                pattern[i * 4 + 0] = x1;
                pattern[i * 4 + 1] = y1;
                pattern[i * 4 + 2] = x2;
                pattern[i * 4 + 3] = y2;
            }

            return pattern;
        }

        /// <summary>
        /// Köşenin 256 bitlik imzasını üretir.
        /// </summary>
        /// <returns>
        /// 32 baytlık tanımlayıcı, ya da köşe kenara yeterince uzak değilse <c>null</c> —
        /// eksik yamadan üretilen imza sessizce yanlış eşleşme üretir, üretmemek daha iyidir.
        /// </returns>
        public static byte[]? Describe(byte[] gray, int width, int height, KeyPoint kp)
        {
            ArgumentNullException.ThrowIfNull(gray);

            int margin = SampleRadius + SmoothRadius;
            if (kp.X < margin || kp.Y < margin || kp.X >= width - margin || kp.Y >= height - margin)
                return null;

            double cos = Math.Cos(kp.Angle);
            double sin = Math.Sin(kp.Angle);
            var descriptor = new byte[Bytes];

            for (int i = 0; i < Tests; i++)
            {
                int p = i * 4;

                int a = SmoothedAt(gray, width, kp.X, kp.Y, Pattern[p], Pattern[p + 1], cos, sin);
                int b = SmoothedAt(gray, width, kp.X, kp.Y, Pattern[p + 2], Pattern[p + 3], cos, sin);

                if (a < b) descriptor[i >> 3] |= (byte)(1 << (i & 7));
            }

            return descriptor;
        }

        /// <summary>
        /// Test noktasını köşenin yönelimiyle döndürüp, oradaki 5×5 kutunun ortalamasını okur.
        ///
        /// <para>Yumuşatma BRIEF için ŞART: tek piksel okumak sensör gürültüsünü doğrudan bite
        /// çevirir ve aynı sahnenin iki karesi farklı imza üretir.</para>
        /// </summary>
        private static int SmoothedAt(
            byte[] gray, int width, int cx, int cy, int dx, int dy, double cos, double sin)
        {
            int rx = cx + (int)Math.Round(dx * cos - dy * sin);
            int ry = cy + (int)Math.Round(dx * sin + dy * cos);

            int sum = 0;
            for (int j = -SmoothRadius; j <= SmoothRadius; j++)
            {
                int rowBase = (ry + j) * width + rx;
                for (int i = -SmoothRadius; i <= SmoothRadius; i++)
                    sum += gray[rowBase + i];
            }

            return sum;   // bölmeye gerek yok: yalnız a < b karşılaştırılıyor
        }

        /// <summary>İki tanımlayıcı arasındaki Hamming uzaklığı (0-256).</summary>
        public static int Hamming(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != Bytes || b.Length != Bytes)
                throw new ArgumentException($"Tanımlayıcı {Bytes} bayt olmalı.");

            int distance = 0;
            for (int i = 0; i < Bytes; i++)
                distance += System.Numerics.BitOperations.PopCount((uint)(a[i] ^ b[i]));

            return distance;
        }
    }
}
