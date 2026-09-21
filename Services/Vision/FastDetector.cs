using System;
using System.Collections.Generic;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>
    /// Bir köşe noktası: konum, güç ve yönelim (radyan).
    /// </summary>
    /// <param name="X">Piksel sütunu.</param>
    /// <param name="Y">Piksel satırı.</param>
    /// <param name="Score">Köşe gücü — bastırma ve sıralama için; mutlak bir anlamı yoktur.</param>
    /// <param name="Angle">
    /// Yoğunluk merkezinden türetilen yönelim. Tanımlayıcı bu açıyla döndürülerek okunur;
    /// kamera eğildiğinde aynı desenin aynı tanımlayıcıyı üretmesini bu sağlar.
    /// </param>
    public readonly record struct KeyPoint(int X, int Y, int Score, double Angle);

    /// <summary>
    /// FAST-9 KÖŞE BULUCU — ORB'un ilk aşaması.
    ///
    /// <para><b>Neden elle yazılıyor:</b> enclave'de OpenCV yok ve olmayacak; içeriye doğrulanmamış
    /// üçüncü taraf ikili dosya sokmak, tüm güven modelinin dayandığı "kaynağı derle, PCR0'ı
    /// karşılaştır" iddiasını zayıflatır. Kod burada duruyor, okunabiliyor, deterministik.</para>
    ///
    /// <para><b>Neden ORB, neden ucuz bir alternatif değil:</b> beş ucuz yöntem denendi ve beşi de
    /// çöktü (şablon arama, ölçek taraması, üç farklı yama-oranı kurgusu). Kök sebep hepsinin bir
    /// HAREKET MODELİ varsaymasıydı; oysa düzlemsel bir sahnenin gerçek hareketi parametreleri
    /// bilinmeyen bir homografidir. ORB'u çalıştıran şey tanımlayıcının kendisi değil, hareketi
    /// bilmeden eşleştirip aykırıları RANSAC ile atabilmesidir.</para>
    ///
    /// <para><b>Bu sınıfın işi:</b> yalnız köşe bulmak ve her köşeye bir yönelim atamak. Tanımlayıcı,
    /// eşleştirme ve RANSAC ayrı parçalardır — her biri kendi başına doğrulanabilsin diye bölündü.</para>
    ///
    /// <para><b>Algoritma:</b> merkez pikselin çevresindeki 3 yarıçaplı Bresenham çemberi üzerindeki
    /// 16 nokta okunur. Bu noktaların ARDIŞIK en az 9 tanesi merkezden eşik kadar parlak ya da eşik
    /// kadar koyuysa nokta köşedir. Ardışıklık şartı, kenarları eler: bir kenar çemberi ikiye böler,
    /// köşe ise tek bir yay bırakır.</para>
    ///
    /// <para>⚠️ Bu aşama tek başına hiçbir şey kanıtlamaz; ürettiği noktalar yalnız sonraki
    /// aşamaların girdisidir.</para>
    /// </summary>
    public static class FastDetector
    {
        /// <summary>Köşe sayılmak için gereken ARDIŞIK nokta sayısı.</summary>
        private const int ContiguousNeeded = 9;

        /// <summary>
        /// Yönelim yamasının yarıçapı (ORB makalesindeki 31×31 yamaya karşılık gelir).
        /// Nokta bu kadar kenardan içeride değilse yönelimi güvenilir hesaplanamaz.
        /// </summary>
        public const int OrientationRadius = 15;

        /// <summary>
        /// 3 yarıçaplı Bresenham çemberi, saat yönünde. Sıra ÖNEMLİ: ardışıklık bu diziye göre
        /// tanımlanıyor, karıştırılırsa köşe ile kenar ayrımı bozulur.
        /// </summary>
        private static readonly (int dx, int dy)[] Circle =
        [
            (0, -3), (1, -3), (2, -2), (3, -1), (3, 0), (3, 1), (2, 2), (1, 3),
            (0, 3), (-1, 3), (-2, 2), (-3, 1), (-3, 0), (-3, -1), (-2, -2), (-1, -3),
        ];

        /// <summary>
        /// Gri tonlamalı görüntüde köşeleri bulur, bastırır ve yönelimlerini hesaplar.
        /// </summary>
        /// <param name="gray">Satır-major, piksel başına bir bayt.</param>
        /// <param name="width">Görüntü genişliği.</param>
        /// <param name="height">Görüntü yüksekliği.</param>
        /// <param name="threshold">
        /// Merkez ile çember noktası arasındaki asgari fark. Küçük değer çok nokta ve çok gürültü,
        /// büyük değer dokusuz yüzeylerde hiç nokta demektir. Arka plan dokusu ölçümüyle birlikte
        /// kalibre edilecek; 20 makul bir başlangıç.
        /// </param>
        /// <param name="exclude">
        /// Dışlanacak dikdörtgen (yüz bölgesi). Ölçülmek istenen şey ARKA PLANIN ölçeğidir; yüzün
        /// kendi noktaları payda ile payı karıştırır. null ise tüm kare taranır.
        /// </param>
        /// <param name="maxPoints">
        /// Skora göre en güçlü kaç nokta döndürülecek. Eşleştirme maliyeti nokta sayısının karesiyle
        /// büyüdüğü için tavan şart; 0 veya negatif ise sınır uygulanmaz.
        /// </param>
        public static List<KeyPoint> Detect(
            byte[] gray,
            int width,
            int height,
            int threshold = 20,
            Rect? exclude = null,
            int maxPoints = 1500)
        {
            ArgumentNullException.ThrowIfNull(gray);
            if (width <= 0 || height <= 0) return [];
            if (gray.Length < width * height)
                throw new ArgumentException("Görüntü arabelleği genişlik×yükseklik'ten küçük.", nameof(gray));

            // Yönelim yamasına yer kalmayan kenar şeridi hiç taranmaz: yönelimsiz bir nokta
            // sonraki aşamada zaten kullanılamaz, bulup atmak boşuna iş olur.
            int border = OrientationRadius;
            if (width <= 2 * border || height <= 2 * border) return [];

            // Skor haritası bastırma için: köşe olmayan yerler 0 kalır.
            var scores = new int[width * height];
            var found = new List<(int x, int y)>();

            for (int y = border; y < height - border; y++)
            {
                for (int x = border; x < width - border; x++)
                {
                    if (exclude is { } r && r.Contains(x, y)) continue;

                    int score = CornerScore(gray, width, x, y, threshold);
                    if (score <= 0) continue;

                    scores[y * width + x] = score;
                    found.Add((x, y));
                }
            }

            // Bastırma: 3×3 komşuluğunda en güçlü olmayan noktalar atılır. Bu olmadan tek bir
            // köşe, çevresindeki 8 pikselle birlikte dokuz kez raporlanır ve eşleştirme
            // neredeyse aynı noktalar arasında boğulur.
            var peaks = new List<(int x, int y, int score)>(found.Count);
            foreach (var (x, y) in found)
            {
                int s = scores[y * width + x];
                if (!IsLocalMaximum(scores, width, x, y, s)) continue;
                peaks.Add((x, y, s));
            }

            // 🔴 Tavan, YÖNELİMDEN ÖNCE uygulanır. Yönelim 15 yarıçaplı dairesel yamayı tarar
            // (~700 piksel); her yerel maksimum için hesaplamak, sonra fazlasını atmak demek,
            // atılacak noktalar için baştan çalışmak demektir. Yüksek entropili bir karede
            // (gürültü, doku bombardımanı) tepe sayısı on binlere çıkıyor ve ölçüm 1 saniyeyi
            // aşıyordu — yamalanmış bir istemcinin enclave CPU'sunu yakmasına açık bir yüzey.
            // Sıra değişince maliyet kademe başına `maxPoints` ile SINIRLI hale geliyor.
            if (maxPoints > 0 && peaks.Count > maxPoints)
            {
                peaks.Sort(static (a, b) => b.score.CompareTo(a.score));
                peaks.RemoveRange(maxPoints, peaks.Count - maxPoints);
            }

            var keyPoints = new List<KeyPoint>(peaks.Count);
            foreach (var (x, y, s) in peaks)
                keyPoints.Add(new KeyPoint(x, y, s, Orientation(gray, width, height, x, y)));

            return keyPoints;
        }

        /// <summary>
        /// Noktanın köşe gücü; köşe değilse 0.
        ///
        /// <para>Güç, yayın eşiği ne kadar aştığının toplamıdır. Mutlak bir anlamı yoktur — yalnız
        /// "hangisi daha güçlü" sorusunu cevaplar, bastırma ve tavan uygulaması buna bakar.</para>
        /// </summary>
        private static int CornerScore(byte[] gray, int width, int x, int y, int threshold)
        {
            int center = gray[y * width + x];
            int hi = center + threshold;
            int lo = center - threshold;

            // Hızlı eleme: çemberin 4 ana yönüne (1, 5, 9, 13. noktalar) bak. Dokusuz yüzeylerde
            // piksellerin ezici çoğunluğu buradan düşer ve tam kontrol hiç çalışmaz.
            //
            // 🔴 EŞİK 2, 3 DEĞİL. 16 noktalık çemberde 9 ardışıklık, 4 aralıklı ana yönlerden
            // EN AZ İKİSİNİ içermek zorundadır (9'luk pencere 2 ya da 3 tanesini kapsar) —
            // üçünü şart koşmak geçerli köşeleri eler. "3'te 4" kuralı FAST-12'ye aittir ve
            // ilk sürümde buraya yanlışlıkla o yazıldı: kare testinde DÖRT köşenin dördü birden
            // kayboldu, çünkü dik açıda ana yönlerden yalnız ikisi yayın içinde kalıyor.
            int brightQuad = 0, darkQuad = 0;
            for (int k = 0; k < 16; k += 4)
            {
                int v = gray[(y + Circle[k].dy) * width + (x + Circle[k].dx)];
                if (v > hi) brightQuad++;
                else if (v < lo) darkQuad++;
            }
            if (brightQuad < 2 && darkQuad < 2) return 0;

            Span<int> ring = stackalloc int[16];
            for (int k = 0; k < 16; k++)
                ring[k] = gray[(y + Circle[k].dy) * width + (x + Circle[k].dx)];

            int bright = ArcStrength(ring, hi, brighter: true);
            int dark = ArcStrength(ring, lo, brighter: false);
            return Math.Max(bright, dark);
        }

        /// <summary>
        /// En uzun ardışık yayın gücü; yay <see cref="ContiguousNeeded"/>'a ulaşmıyorsa 0.
        /// Çember dairesel olduğu için tarama 16'yı aşıp başa dönebilmeli.
        /// </summary>
        private static int ArcStrength(ReadOnlySpan<int> ring, int limit, bool brighter)
        {
            int run = 0, sum = 0, best = 0;

            for (int k = 0; k < 16 + ContiguousNeeded; k++)
            {
                int v = ring[k % 16];
                bool inArc = brighter ? v > limit : v < limit;

                if (inArc)
                {
                    run++;
                    sum += brighter ? v - limit : limit - v;
                    if (run >= ContiguousNeeded && sum > best) best = sum;
                }
                else
                {
                    run = 0;
                    sum = 0;
                }
            }

            return best;
        }

        /// <summary>3×3 komşuluğunda kendinden güçlü komşusu yok mu.</summary>
        private static bool IsLocalMaximum(int[] scores, int width, int x, int y, int score)
        {
            for (int dy = -1; dy <= 1; dy++)
            {
                for (int dx = -1; dx <= 1; dx++)
                {
                    if (dx == 0 && dy == 0) continue;
                    // Eşitlikte SOL-ÜST kazanır: aksi hâlde aynı skorlu iki komşu birbirini eler
                    // ve düz kenarlarda köşe tamamen kaybolur.
                    int other = scores[(y + dy) * width + (x + dx)];
                    if (other > score) return false;
                    if (other == score && (dy < 0 || (dy == 0 && dx < 0))) return false;
                }
            }
            return true;
        }

        /// <summary>
        /// YOĞUNLUK MERKEZİ YÖNELİMİ (ORB makalesi §3).
        ///
        /// <para>Yama içindeki parlaklık merkezinin, yamanın geometrik merkezine göre yönü.
        /// Köşe tanımı gereği parlaklık asimetriktir, dolayısıyla bu yön kararlıdır ve görüntü
        /// döndüğünde onunla birlikte döner. Tanımlayıcı bu açıyla okunacağı için, aynı desen
        /// farklı kamera eğiminde aynı biti üretir.</para>
        ///
        /// <para>Yama DAİRESEL: kare bir yama, köşegen yönlerde daha çok piksel taşıdığı için
        /// açıya sistematik bir yanlılık sokar.</para>
        /// </summary>
        internal static double Orientation(byte[] gray, int width, int height, int cx, int cy)
        {
            int r = OrientationRadius;
            int r2 = r * r;
            long m01 = 0, m10 = 0;

            for (int dy = -r; dy <= r; dy++)
            {
                int yy = cy + dy;
                if (yy < 0 || yy >= height) continue;
                int span = (int)Math.Sqrt(r2 - dy * dy);
                int rowBase = yy * width;

                for (int dx = -span; dx <= span; dx++)
                {
                    int xx = cx + dx;
                    if (xx < 0 || xx >= width) continue;
                    int v = gray[rowBase + xx];
                    m10 += (long)dx * v;
                    m01 += (long)dy * v;
                }
            }

            return Math.Atan2(m01, m10);
        }
    }

    /// <summary>Tam sayı dikdörtgen — yüz bölgesini dışlamak için.</summary>
    public readonly record struct Rect(int X, int Y, int Width, int Height)
    {
        public bool Contains(int px, int py) =>
            px >= X && px < X + Width && py >= Y && py < Y + Height;
    }
}
