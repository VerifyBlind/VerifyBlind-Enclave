using System;
using System.Collections.Generic;

namespace VerifyBlind.Enclave.Services.FaceAlignment
{
    /// <summary>
    /// Burnun kanonik şablona göre sapması — YÖN'lü (kanonik gözler-arası mesafenin oranı).
    /// Büyüklük değil vektör taşınır; gerekçe <see cref="PlanarityProbe.MedianOffset"/>'te.
    /// </summary>
    public readonly record struct NoseOffset(double X, double Y)
    {
        public double Magnitude => Math.Sqrt(X * X + Y * Y);

        public static double Distance(NoseOffset a, NoseOffset b)
        {
            double dx = a.X - b.X, dy = a.Y - b.Y;
            return Math.Sqrt(dx * dx + dy * dy);
        }
    }

    /// <summary>
    /// DÜZLEM-DIŞILIK SINAMASI — "kameranın önündeki yüz üç boyutlu mu, yoksa düz bir yüzey mi?"
    ///
    /// <para><b>Neden var:</b> doku tabanlı anti-spoof (MiniFASNet) monitör hilesini ölçümlerimizde
    /// 14 denemenin 6'sında kaçırdı ve eşik oynatmak çözmüyor — meşru girişlerin en kötü karesiyle
    /// saldırının en iyi karesi çakışıyor (P(live) 0,817 ↔ 0,822). Doku bir MODEL hükmüdür ve
    /// yanılabilir. Buradaki sinyal ise GEOMETRİDİR: düz bir yüzey gerçekten düzdür.</para>
    ///
    /// <para><b>Fizik:</b> gerçek yüzde burun ucu, gözler ve ağız köşelerinin oluşturduğu düzlemin
    /// ~20 mm ÖNÜNDEDİR. Kamera yaklaştıkça burun, düzlemdeki noktalardan daha çok büyür — yüzün
    /// izdüşüm ŞEKLİ değişir. Ekrandaki bir yüz ise düzlemseldir: kamera hareketi tüm noktalara
    /// AYNI homografiyi uygular, dolayısıyla şekil hiç değişmez.</para>
    ///
    /// <para><b>Ölçüm:</b> gözler + ağız köşeleri (4 nokta) kabaca eş düzlemlidir. Bu dördünü
    /// ArcFace kanonik şablonuna taşıyan homografi TEK olarak belirlenir (4 eşleşme = 8 bilinmeyen).
    /// Aynı homografi burna uygulanır ve kanonik burun konumundan sapması ölçülür:
    /// <b>burun sapma vektörü</b>. Düzlemsel bir nesnede bu vektör kamera hareketinden
    /// BAĞIMSIZDIR (homografiler bileşiktir → ekrandaki fotoğrafın kendi perspektifi sabit kalır);
    /// gerçek yüzde mesafeyle DEĞİŞİR.</para>
    ///
    /// <para><b>Sinyal:</b> uzak ve yakın pencerelerin sapma vektörleri arasındaki UZAKLIK.
    /// Düz yüzeyde tam sıfır (sentetik testte 0,000000), gerçek yüzde 60→25 cm'de kanonik
    /// gözler-arası mesafenin ~%3'ü.</para>
    ///
    /// <para>⚠️ Bu sınıf tek başına karar VERMEZ. Bir SAYI üretir; eşiği canlı veriyle kalibre
    /// edilir. Ölçüm önce yalnız kaydedilir (kapı kapalı).</para>
    ///
    /// <para>⚠️ Ölçümü ENCLAVE yapar, telefon değil. Telefonun ML Kit'i daha zengin nokta kümesi
    /// verir (kulak, yanak) ama istemci güvenilmeyen taraftır; burada girdi yalnız görüntülerdir
    /// ve 5 noktayı YuNet enclave içinde çıkarır.</para>
    /// </summary>
    public static class PlanarityProbe
    {
        /// <summary>
        /// Landmark dizisindeki nokta sırası (YuNet ve ArcFace şablonu ile aynı):
        /// 0=sağ göz, 1=sol göz, 2=burun, 3=sağ ağız köşesi, 4=sol ağız köşesi.
        /// Dizi düzeni x0,y0,x1,y1,...,x4,y4 (10 eleman).
        /// </summary>
        public const int LandmarkCount = 5;

        /// <summary>ArcFace kanonik 5-nokta şablonu (112x112) — <see cref="FaceAligner"/> ile AYNI.</summary>
        private static readonly double[] Canonical =
        {
            38.2946, 51.6963,   // sağ göz
            73.5318, 51.5014,   // sol göz
            56.0252, 71.7366,   // burun
            41.5493, 92.3655,   // sağ ağız
            70.7299, 92.2041    // sol ağız
        };

        /// <summary>Homografiye giren dört EŞ DÜZLEMLİ nokta: gözler + ağız köşeleri.</summary>
        private static readonly int[] PlanarIdx = { 0, 1, 3, 4 };

        /// <summary>
        /// Kanonik şablonun gözler-arası mesafesi. Sapmayı buna bölerek ölçekten bağımsız,
        /// okunabilir bir oran elde ederiz (0,03 = gözler-arası mesafenin %3'ü kadar sapma).
        /// </summary>
        public static readonly double CanonicalInterocular =
            Math.Sqrt(Math.Pow(Canonical[2] - Canonical[0], 2) + Math.Pow(Canonical[3] - Canonical[1], 2));

        /// <summary>
        /// Tek karenin burun sapma VEKTÖRÜ — kanonik gözler-arası mesafenin oranı olarak.
        ///
        /// <para>Dört düzlemsel nokta (gözler + ağız köşeleri) kanonik şablona homografiyle
        /// taşınır; aynı homografi burna uygulanıp kanonik burunla farkı alınır.</para>
        ///
        /// <para>Noktalar bozuksa (NaN, çakışık, dejenere dörtgen) <c>null</c> döner — ölçüm
        /// yapılamadı demektir, "geçti" ya da "kaldı" demek DEĞİLDİR.</para>
        /// </summary>
        public static NoseOffset? NoseResidualVector(float[]? landmarks)
        {
            if (landmarks is not { Length: LandmarkCount * 2 }) return null;

            var pts = new double[LandmarkCount * 2];
            for (int i = 0; i < pts.Length; i++)
            {
                double coord = landmarks[i];
                if (double.IsNaN(coord) || double.IsInfinity(coord)) return null;
                pts[i] = coord;
            }

            // Hartley normalizasyonu: görüntü koordinatları binlerce piksel olabilir ve
            // normalize edilmemiş DLT 8x8 sistemi kötü koşullandırır. Dönüşüm bir SIMILARITY
            // olduğundan aynı dönüşümü burna da uygulamak yeterlidir — homografiyi geri
            // bileştirmeye gerek yok, çünkü bize yalnız H(burun) lazım.
            //
            // Ölçek YALNIZ dört düzlemsel noktadan hesaplanır: burun dahil edilseydi, burnun
            // kendi sapması normalizasyonu etkiler ve ölçtüğümüz şeyi kirletirdi.
            double cx = 0, cy = 0;
            foreach (int i in PlanarIdx) { cx += pts[2 * i]; cy += pts[2 * i + 1]; }
            cx /= PlanarIdx.Length; cy /= PlanarIdx.Length;

            double meanDist = 0;
            foreach (int i in PlanarIdx)
            {
                double dx = pts[2 * i] - cx, dy = pts[2 * i + 1] - cy;
                meanDist += Math.Sqrt(dx * dx + dy * dy);
            }
            meanDist /= PlanarIdx.Length;
            if (meanDist < 1e-9) return null;   // dört nokta çakışık

            double s = Math.Sqrt(2.0) / meanDist;

            var srcX = new double[4];
            var srcY = new double[4];
            var dstX = new double[4];
            var dstY = new double[4];
            for (int k = 0; k < 4; k++)
            {
                int i = PlanarIdx[k];
                srcX[k] = (pts[2 * i] - cx) * s;
                srcY[k] = (pts[2 * i + 1] - cy) * s;
                dstX[k] = Canonical[2 * i];
                dstY[k] = Canonical[2 * i + 1];
            }

            double noseX = (pts[4] - cx) * s;
            double noseY = (pts[5] - cy) * s;

            double[]? h = SolveHomography4(srcX, srcY, dstX, dstY);
            if (h == null) return null;

            double w = h[6] * noseX + h[7] * noseY + 1.0;
            if (Math.Abs(w) < 1e-12) return null;   // burun ufuk çizgisine düştü — ölçülemez

            double u = (h[0] * noseX + h[1] * noseY + h[2]) / w;
            double v = (h[3] * noseX + h[4] * noseY + h[5]) / w;
            if (double.IsNaN(u) || double.IsNaN(v) || double.IsInfinity(u) || double.IsInfinity(v))
                return null;

            return new NoseOffset(
                (u - Canonical[4]) / CanonicalInterocular,
                (v - Canonical[5]) / CanonicalInterocular);
        }

        /// <summary>Tek karenin sapma BÜYÜKLÜĞÜ — yalnız teşhis/log için.</summary>
        public static double? NoseResidual(float[]? landmarks) =>
            NoseResidualVector(landmarks)?.Magnitude;

        /// <summary>
        /// Bir kare KÜMESİNİN sapma vektörü — bileşen bazında MEDYAN.
        ///
        /// <para><b>Neden vektör, neden büyüklük değil (sentetik ölçümle bulundu):</b> büyüklük
        /// negatif olamaz, bu yüzden nokta titremesi onu yalnız YUKARI iter — yani gürültü
        /// sıfır-ortalamalı DEĞİLDİR ve kare eklemek yanlılığı gidermez, ona YAKINSAR. İlk
        /// sürümde 3 px titremede kare sayısını artırmak ayrışmayı %35'ten %20'ye DÜŞÜRDÜ.
        /// Vektör uzayında gürültü sıfır-ortalamalıdır; medyan gerçek sapmaya yakınsar.</para>
        ///
        /// <para><b>Neden medyan, neden ortalama değil:</b> tek bir kötü tespit (yanlış yüz,
        /// hareket bulanıklığı, yarı kapalı göz) ortalamayı sürükler, medyanı sürüklemez.</para>
        ///
        /// <para>Hiçbir kare ölçülemezse <c>null</c>.</para>
        /// </summary>
        public static NoseOffset? MedianOffset(IReadOnlyList<float[]>? frames)
        {
            if (frames == null || frames.Count == 0) return null;

            var xs = new List<double>(frames.Count);
            var ys = new List<double>(frames.Count);
            foreach (var f in frames)
            {
                var o = NoseResidualVector(f);
                if (o.HasValue) { xs.Add(o.Value.X); ys.Add(o.Value.Y); }
            }

            if (xs.Count == 0) return null;
            return new NoseOffset(Median(xs), Median(ys));
        }

        private static double Median(List<double> values)
        {
            values.Sort();
            int mid = values.Count / 2;
            return values.Count % 2 == 1 ? values[mid] : (values[mid - 1] + values[mid]) / 2.0;
        }

        /// <summary>
        /// DÜZLEM-DIŞILIK SİNYALİ, kare kümelerinden — üretimde kullanılacak biçim.
        ///
        /// <para>Uzak ve yakın pencerelerin medyan sapma vektörleri arasındaki UZAKLIK.
        /// Büyüklüklerin farkı DEĞİL: vektör farkı yön değişimini de yakalar ve düzlemsel
        /// nesnede tam sıfırdır (vektör kamera hareketinden bağımsızdır).</para>
        /// </summary>
        public static double? Delta(IReadOnlyList<float[]>? farFrames, IReadOnlyList<float[]>? nearFrames)
        {
            var far = MedianOffset(farFrames);
            var near = MedianOffset(nearFrames);
            if (far == null || near == null) return null;
            return NoseOffset.Distance(near.Value, far.Value);
        }

        /// <summary>Tek kare çiftinden sinyal — yalnız teşhis/kıyas için; üretimde kümeler kullanılır.</summary>
        public static double? Delta(float[]? farFrame, float[]? nearFrame)
        {
            var far = NoseResidualVector(farFrame);
            var near = NoseResidualVector(nearFrame);
            if (far == null || near == null) return null;
            return NoseOffset.Distance(near.Value, far.Value);
        }

        /// <summary>
        /// İki noktanın (gözlerin) arasındaki mesafe — "kullanıcı gerçekten yaklaştı mı" kapısı.
        ///
        /// <para>⚠️ Bu tek başına SAHTECİLİK ölçüsü DEĞİLDİR: monitöre yaklaşınca ekrandaki yüz de
        /// aynı oranda büyür. Yalnız hareketin gerçekleştiğini doğrular; ayırt eden şey
        /// <see cref="Delta(IReadOnlyList{float[]}, IReadOnlyList{float[]})"/>'dır. Yaklaşma
        /// olmadan Delta'nın anlamı yoktur (sinyal mesafe değişiminden doğar), bu yüzden ikisi
        /// birlikte okunur.</para>
        /// </summary>
        public static double? Interocular(float[]? landmarks)
        {
            if (landmarks is not { Length: LandmarkCount * 2 }) return null;
            double dx = landmarks[2] - landmarks[0];
            double dy = landmarks[3] - landmarks[1];
            if (double.IsNaN(dx) || double.IsNaN(dy)) return null;
            double d = Math.Sqrt(dx * dx + dy * dy);
            return d < 1e-9 ? null : d;
        }

        /// <summary>Bir kare kümesinin medyan gözler-arası mesafesi (ölçülemeyenler atlanır).</summary>
        public static double? MedianInterocular(IReadOnlyList<float[]>? frames)
        {
            if (frames == null || frames.Count == 0) return null;
            var values = new List<double>(frames.Count);
            foreach (var f in frames)
            {
                double? d = Interocular(f);
                if (d.HasValue) values.Add(d.Value);
            }
            return values.Count == 0 ? null : Median(values);
        }

        /// <summary>
        /// Dört nokta eşleşmesinden homografi (DLT): [h11,h12,h13, h21,h22,h23, h31,h32],
        /// h33 = 1 sabit. Sistem tekse null.
        /// </summary>
        private static double[]? SolveHomography4(
            double[] sx, double[] sy, double[] dx, double[] dy)
        {
            // Her eşleşme iki satır verir:
            //   x·h11 + y·h12 + h13                     − u·x·h31 − u·y·h32 = u
            //                         x·h21 + y·h22 + h23 − v·x·h31 − v·y·h32 = v
            var a = new double[8, 9];
            for (int i = 0; i < 4; i++)
            {
                int r = 2 * i;
                a[r, 0] = sx[i]; a[r, 1] = sy[i]; a[r, 2] = 1;
                a[r, 6] = -dx[i] * sx[i]; a[r, 7] = -dx[i] * sy[i]; a[r, 8] = dx[i];

                r++;
                a[r, 3] = sx[i]; a[r, 4] = sy[i]; a[r, 5] = 1;
                a[r, 6] = -dy[i] * sx[i]; a[r, 7] = -dy[i] * sy[i]; a[r, 8] = dy[i];
            }

            return GaussianSolve(a);
        }

        /// <summary>Kısmi pivotlamalı Gauss eliminasyonu — 8x9 artırılmış matris, 8 bilinmeyen.</summary>
        private static double[]? GaussianSolve(double[,] a)
        {
            const int n = 8;

            for (int col = 0; col < n; col++)
            {
                int pivot = col;
                double best = Math.Abs(a[col, col]);
                for (int r = col + 1; r < n; r++)
                {
                    double mag = Math.Abs(a[r, col]);
                    if (mag > best) { best = mag; pivot = r; }
                }

                // Tekil (ya da tekile çok yakın) sistem: dejenere dörtgen — ölçüm yapılamaz.
                if (best < 1e-12) return null;

                if (pivot != col)
                    for (int c = col; c <= n; c++)
                        (a[col, c], a[pivot, c]) = (a[pivot, c], a[col, c]);

                double p = a[col, col];
                for (int r = col + 1; r < n; r++)
                {
                    double f = a[r, col] / p;
                    if (f == 0) continue;
                    for (int c = col; c <= n; c++) a[r, c] -= f * a[col, c];
                }
            }

            var x = new double[n];
            for (int r = n - 1; r >= 0; r--)
            {
                double sum = a[r, n];
                for (int c = r + 1; c < n; c++) sum -= a[r, c] * x[c];
                x[r] = sum / a[r, r];
                if (double.IsNaN(x[r]) || double.IsInfinity(x[r])) return null;
            }

            return x;
        }
    }
}
