using System;
using System.Collections.Generic;

namespace VerifyBlind.Enclave.Services.Vision
{
    /// <summary>Arka plan ölçeği kestirimi ve ne kadar veriye dayandığı.</summary>
    /// <param name="Scale">B karesinin A karesine göre arka plan ölçeği.</param>
    /// <param name="Inliers">Modele uyan eşleşme sayısı — güvenin ölçüsü.</param>
    /// <param name="Matches">Uydurma öncesi toplam eşleşme sayısı.</param>
    public readonly record struct BackgroundScale(double Scale, int Inliers, int Matches);

    /// <summary>
    /// ARKA PLAN ÖLÇEĞİ — parallaks oranının PAYDASI.
    ///
    /// <para><b>Ölçülen fikir:</b> telefon uzaklaşıp yaklaşırken yüz ve arka plan farklı
    /// derinlikte oldukları için farklı oranda büyür. Düz bir yüzeyde (ekran, baskı) ikisi AYNI
    /// düzlemdedir ve aynı oranda büyür:
    /// <code>
    /// B = yüz ölçeği / arka plan ölçeği
    ///   düz yüzey  → 1,00   (fizik sabiti, ölçüm değil)
    ///   gerçek yüz → 1,38 - 1,59
    /// </code>
    /// Bu sınıf paydayı üretir; payı (yüz ölçeği) çağıran kendi ölçer.</para>
    ///
    /// <para><b>Yüz DIŞLANIR.</b> Dışlanmazsa yüzün kendi noktaları paydaya karışır, payda paya
    /// yaklaşır ve oran 1'e çekilir — yani saldırıyı meşru gösterir. Dışlama bir eniyileme değil,
    /// ölçümün tanımının parçası.</para>
    ///
    /// <para>⚠️ <c>null</c> dönüşü "ölçemedik" demektir, "sahte" DEĞİL. Dokusuz bir duvarın
    /// önündeki meşru kullanıcı ölçülemez ve reddedilmemelidir; bu sözleşme kapı açıldığında da
    /// korunmalı.</para>
    /// </summary>
    public static class BackgroundScaleEstimator
    {
        /// <summary>
        /// 🔴 ÖLÇÜM HALKASI: öznitelikler yüz kutusunun bu katına kadar olan bantta aranır,
        /// tüm karede DEĞİL.
        ///
        /// <para><b>Neden:</b> saldırganın ekranı kadrajı doldurmazsa, kenarlarda kalan GERÇEK
        /// oda gerçek derinliktedir. Yüz ekran düzleminde, arka plan gerçek odada olunca oran
        /// 1'in belirgin üstüne çıkar ve düzenek meşru görünür — sahada tam bu oldu
        /// (2026-09-22, 7. koşu: monitörde canlı kamera, kadrajda perde, B = 1,179; aynı
        /// monitörde kadrajı dolduran sabit fotoğraf ise 0,963).</para>
        ///
        /// <para><b>Halka bunu kapıyor:</b> saldırgan artık yüzün ÇEVRESİNİ de ekranla
        /// kaplamak zorunda. Kapladığı anda halka ekran düzlemine düşer ve B ≈ 1,00 çıkar.
        /// Kaçamak, yakalandığı duruma dönüşür. Meşru kullanıcı için değişen bir şey yok:
        /// başının hemen arkasındaki duvar zaten bu bantta.</para>
        ///
        /// <para>Yakın karede yüz kutusu zaten kadrajın yarısını kapladığı için halka doğal
        /// olarak "yüz dışındaki her yer"e yakınsar; kısıt kendiliğinden gevşer.</para>
        /// </summary>
        public const double RingFactor = 2.2;

        /// <summary>Yüz kutusundan ölçüm halkasını türetir.</summary>
        internal static Rect? RingAround(Rect? face)
        {
            if (face is not { } f) return null;
            double cx = f.X + f.Width / 2.0, cy = f.Y + f.Height / 2.0;
            double hw = f.Width * RingFactor / 2.0, hh = f.Height * RingFactor / 2.0;
            return new Rect((int)(cx - hw), (int)(cy - hh), (int)(2 * hw), (int)(2 * hh));
        }

        /// <summary>
        /// İki karenin arka planı arasındaki ölçek değişimini kestirir.
        /// </summary>
        /// <param name="faceA">A karesindeki yüz kutusu (dışlanır); bilinmiyorsa null.</param>
        /// <param name="faceB">B karesindeki yüz kutusu (dışlanır); bilinmiyorsa null.</param>
        public static BackgroundScale? Estimate(
            byte[] grayA, int widthA, int heightA, Rect? faceA,
            byte[] grayB, int widthB, int heightB, Rect? faceB)
        {
            var a = OrbExtractor.Extract(grayA, widthA, heightA, faceA, include: RingAround(faceA));
            var b = OrbExtractor.Extract(grayB, widthB, heightB, faceB, include: RingAround(faceB));

            var matches = FeatureMatcher.Match(a, b);
            if (matches.Count < SimilarityRansac.MinInliers) return null;

            var pairs = new List<PointPair>(matches.Count);
            foreach (var m in matches)
                pairs.Add(new PointPair(
                    a[m.A].X, a[m.A].Y, b[m.B].X, b[m.B].Y,
                    Math.Max(a[m.A].Scale, b[m.B].Scale)));

            var fit = SimilarityRansac.Estimate(pairs);
            if (fit is not { } f) return null;

            return new BackgroundScale(f.Scale, f.Inliers, matches.Count);
        }

        /// <summary>
        /// Parallaks oranı: <paramref name="faceScale"/> / arka plan ölçeği.
        ///
        /// <para>Yüz ölçeği çağıranın kendi ölçümüdür (enclave'de göz-arası mesafe oranı);
        /// istemcinin beyanı DEĞİL. İki sayının da aynı kare çiftinden gelmesi şarttır, yoksa
        /// oran iki farklı hareketi kıyaslar ve anlamsızdır.</para>
        /// </summary>
        public static double? ParallaxRatio(double faceScale, BackgroundScale? background)
        {
            if (background is not { } bg) return null;
            if (bg.Scale <= 0 || faceScale <= 0) return null;
            return faceScale / bg.Scale;
        }
    }
}
