using System;
using System.Collections.Generic;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.FaceAlignment;
using VerifyBlind.Enclave.Services.Vision;

namespace VerifyBlind.Enclave.Services
{
    /// <summary>
    /// Parallaks kanıtını ÖLÇER — karar vermez.
    ///
    /// <para><b>Ölçülecek sinyal:</b> yüz ve arka plan farklı derinlikte olduğu için telefon
    /// uzaklaşıp yaklaşırken farklı oranda büyür. Düz yüzeyde ikisi aynı düzlemdedir ve aynı
    /// oranda büyür — oran <b>1,00</b> olur. Fotoğraf ölçümünde ekran 0,997-1,025 (iki farklı
    /// cihazda), gerçek yüz 1,38-1,59 verdi.</para>
    ///
    /// <para><b>Sinyal artık hesaplanıyor.</b> Arka planın ölçeğini çıkaran ORB elle yazıldı
    /// (<see cref="Vision.OrbExtractor"/> → <see cref="Vision.FeatureMatcher"/> →
    /// <see cref="Vision.SimilarityRansac"/>). Beş ucuz alternatif önce denenip çökmüştü: hepsi
    /// bir hareket modeli VARSAYIYORDU, oysa düzlemsel sahnenin gerçek hareketi parametreleri
    /// bilinmeyen bir homografi. ORB'u çalıştıran şey tanımlayıcı değil, hareketi bilmeden
    /// eşleştirip RANSAC ile aykırıları ATMASI.</para>
    ///
    /// <para>Toplanan: kaç karede yüz bulunabildi, yüzün gerçek açıklığı (istemcinin bildirdiğine
    /// GÜVENMEDEN, YuNet ile), istemcinin arka plan doku ölçümü ve <b>B oranı</b>.</para>
    ///
    /// <para>🔴 <b>Eşik hâlâ YOK.</b> B ölçülüyor ve kaydediliyor, ama hiçbir akışı reddetmiyor.
    /// Eşik canlı meşru dağılım görülmeden konmayacak — p_live'da tam olarak bu sırayı atlayıp
    /// meşru kullanıcıyı reddetme hatasına düşmüştük.</para>
    ///
    /// <para>⚠️ Hiçbir kaydı reddetmez. "Ölçemedik" ile "sahte" ayrı şeylerdir ve kapı
    /// açıldığında da ayrı kalmalı: ölçülemeyen akışı reddetmek, düz duvarın önündeki meşru
    /// kullanıcıyı giriş yapamaz hale getirir.</para>
    /// </summary>
    public interface IPlanarityMeasurementService
    {
        PlanarityOutcome Measure(ParallaxProof? proof);
    }

    /// <inheritdoc cref="IPlanarityMeasurementService"/>
    public class PlanarityMeasurementService : IPlanarityMeasurementService
    {
        /// <summary>
        /// İşlenecek EN FAZLA kare. Her kare bir YuNet çıkarımıdır; sınırsız kare register'ı
        /// ucuz bir CPU tüketim yüzeyine çevirirdi (aday listesindeki "tavan iki" ile aynı gerekçe).
        /// </summary>
        public const int MaxFrames = 8;

        /// <summary>Parallaks için en az bu kadar ölçülebilir kare gerekir (uzak + yakın).</summary>
        public const int MinFrames = 2;

        /// <summary>Tek karenin çözülmüş en büyük boyutu — şişirilmiş yük koruması.</summary>
        private const int MaxFrameBytes = 400_000;

        /// <summary>
        /// B için ölçülecek EN FAZLA ardışık kare çifti.
        ///
        /// <para>Ölçüldü: gerçekçi bir sahnede çift başına ~175 ms (240×320), yüksek entropili
        /// bir karede ~830 ms (360×480). İkincisi yamalanmış bir istemcinin enclave CPU'sunu
        /// yakmak için kullanabileceği bir yüzey; çift sayısını sınırlamak onu sabitler.
        /// Medyan için dört çift zaten fazlasıyla yeterli.</para>
        /// </summary>
        private const int MaxRatioPairs = 4;

        /// <summary>
        /// İstemcinin bildirdiği doku bu değerin altındaysa ölçüm "dokusuz" sayılır.
        /// ⚠️ İstemciden gelir ve DOĞRULANMAZ; yalnız etiketleme içindir, karar değil.
        ///
        /// <para><b>18 → 14 (2026-09-19), ilk gerçek dağılımdan.</b> Çıplak duvar 10,8-13,6;
        /// mutfak/perde/tablolu duvar/gece penceresi 14,2-16,1; kitaplık ve koridor 18,1-19,3.
        /// 18 eşiği yedi meşru sahnenin beşini "dokusuz" etiketliyordu. Değer istemcideki
        /// <c>MIN_BACKGROUND_TEXTURE</c> ile AYNI olmak zorunda: farklı olurlarsa kullanıcı
        /// uyarı almadan geçer ama satır <c>no_texture</c> yazılır (ya da tersi).</para>
        /// </summary>
        private const double MinBackgroundTexture = 14.0;

        private readonly IBiometricService _biometric;

        public PlanarityMeasurementService(IBiometricService biometric) => _biometric = biometric;

        public PlanarityOutcome Measure(ParallaxProof? proof)
        {
            if (proof == null)
                return new PlanarityOutcome { Status = PlanarityStatuses.NoProof };

            var outcome = new PlanarityOutcome
            {
                BgTexture = proof.BgTexture,
                ElapsedMs = proof.ElapsedMs,
            };

            // 🔴 Kare YOKSA bile doku ve süre KAYDEDİLİR. Eskiden boş kare listesi daha ilk
            // satırda boş bir sonuçla dönüyordu ve o akışın arka plan dokusu — eşiği kalibre
            // etmek için gereken tek sayı — kayboluyordu. Sahada tam bu oldu: dokusuz arka
            // plan yüzünden hiç kare toplanamayan akıştan geriye sadece "no_proof" kaldı,
            // dokunun KAÇ olduğu ise hiç öğrenilemedi. Ölçemediğimiz akış, neden
            // ölçemediğimizi anlatan akıştır.
            if (proof.Frames.Count == 0)
            {
                outcome.Status = PlanarityStatuses.NoProof;
                Console.WriteLine(
                    $"[Parallax] durum=no_proof kare=0 " +
                    $"doku={proof.BgTexture?.ToString("F1") ?? "-"} süre={proof.ElapsedMs}ms");
                return outcome;
            }

            // Yüzü kendi YuNet'imizle bul — istemcinin bildirdiği genişliklere GÜVENMİYORUZ.
            //
            // Gri piksel ve yüz kutusu da saklanır: B oranının paydası (arka plan ölçeği)
            // ardışık kare ÇİFTLERİ üzerinden hesaplanacak, tek tek karelerden değil.
            var interocular = new List<double>();
            var gray = new List<GrayImage?>();
            var faceBox = new List<Rect>();
            int processed = 0;
            foreach (string b64 in proof.Frames)
            {
                if (processed >= MaxFrames) break;
                if (string.IsNullOrEmpty(b64)) continue;

                byte[] bytes;
                try { bytes = Convert.FromBase64String(b64); }
                catch (FormatException) { continue; }
                if (bytes.Length == 0 || bytes.Length > MaxFrameBytes) continue;

                processed++;
                float[]? lm;
                try { lm = _biometric.DetectLandmarks(bytes); }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Parallax] Kare atlandı: {ex.GetType().Name}");
                    continue;
                }
                double? d = lm is null ? null : PlanarityProbe.Interocular(lm);
                if (d is not > 0 || lm is null) continue;

                interocular.Add(d.Value);
                faceBox.Add(FaceBoxFrom(lm, d.Value));

                // 🔴 Gri çözüm BAŞARISIZ OLURSA kare listeden DÜŞMEZ, yalnız B'ye katılmaz.
                // İlk sürümde düşüyordu ve açıklık ile durum etiketi sessizce değişiyordu:
                // yüzü bulunmuş, açıklığa katkısı olan bir kare, ikincil bir ölçüm yüzünden
                // hiç yokmuş gibi davranıyordu. Ölçümün bir dalı diğerini bozmamalı.
                gray.Add(GrayDecoder.Decode(bytes));
            }

            outcome.FarMeasured = interocular.Count;

            if (interocular.Count == 0)
            {
                outcome.Status = PlanarityStatuses.NoFaceFar;
                return outcome;
            }

            // Kareler en uzaktan en yakına SIRALI geliyor → açıklık = son / ilk.
            // Bunu istemciden almıyoruz: açıklık sinyalin anlamını belirleyen sayı ve
            // istemcinin beyanı doğrulanamaz.
            double span = interocular[^1] / interocular[0];
            outcome.IedRatio = Math.Round(span, 4);

            outcome.Delta = ParallaxRatio(gray, faceBox, interocular);

            if (interocular.Count < MinFrames)
                outcome.Status = PlanarityStatuses.NotEnoughFrames;
            else if (proof.BgTexture is { } t && t < MinBackgroundTexture)
                // Doku yoksa arka plan ölçeği çıkarılamaz — ama bu bir RED sebebi değil.
                outcome.Status = PlanarityStatuses.NoTexture;
            else if (span < 1.2)
                // Kullanıcı yeterince yaklaşmadı → sinyalin anlamı yok.
                outcome.Status = PlanarityStatuses.NotApproached;
            else
                outcome.Status = PlanarityStatuses.Measured;

            Console.WriteLine(
                $"[Parallax] durum={outcome.Status} kare={outcome.FarMeasured}/{proof.Frames.Count} " +
                $"açıklık={span:F2} B={outcome.Delta?.ToString("F3") ?? "-"} " +
                $"doku={proof.BgTexture?.ToString("F1") ?? "-"} " +
                $"tam={proof.Complete}");

            return outcome;
        }

        /// <summary>
        /// PARALLAKS ORANI — <c>B = yüz ölçeği / arka plan ölçeği</c>, ardışık kare çiftlerinin
        /// MEDYANI.
        ///
        /// <para><b>Neden çiftler, neden uzak-yakın tek atlayış değil:</b> iki uç arasındaki
        /// ölçek farkı 2 kata yaklaşıyor ve en yakın karede yüz kutusu kadrajın yarısını
        /// kaplıyor — dışlandıktan sonra geriye eşleştirilecek arka plan pek kalmıyor. Ardışık
        /// duraklar arasındaki ~1,2'lik adımlarda hem örtüşme büyük hem de eşleştirme kolay.</para>
        ///
        /// <para><b>Neden medyan:</b> tek bir çiftte ölçüm bozulabilir (bulanıklık, kadraja giren
        /// nesne). Medyan tek bir kötü çiftten etkilenmez; ortalama etkilenir.</para>
        ///
        /// <para>Hiçbir çift ölçülemezse <c>null</c> — "ölçemedik" demektir, "sahte" DEĞİL.</para>
        /// </summary>
        private static double? ParallaxRatio(
            List<GrayImage?> gray, List<Rect> faceBox, List<double> interocular)
        {
            var ratios = new List<double>();

            for (int i = 0; i + 1 < gray.Count && ratios.Count < MaxRatioPairs; i++)
            {
                if (interocular[i] <= 0) continue;
                if (gray[i] is not { } a || gray[i + 1] is not { } b) continue;
                double faceScale = interocular[i + 1] / interocular[i];

                var background = BackgroundScaleEstimator.Estimate(
                    a.Pixels, a.Width, a.Height, faceBox[i],
                    b.Pixels, b.Width, b.Height, faceBox[i + 1]);

                if (BackgroundScaleEstimator.ParallaxRatio(faceScale, background) is { } r)
                    ratios.Add(r);
            }

            if (ratios.Count == 0) return null;

            ratios.Sort();
            double median = ratios.Count % 2 == 1
                ? ratios[ratios.Count / 2]
                : (ratios[ratios.Count / 2 - 1] + ratios[ratios.Count / 2]) / 2;

            return Math.Round(median, 4);
        }

        /// <summary>
        /// Beş YuNet noktasından kaba yüz kutusu — ORB'un DIŞLAYACAĞI bölge.
        ///
        /// <para>Cömert tutuluyor: kutuya sığmayan saç/çene arka plana karışırsa payda paya
        /// yaklaşır ve oran 1'e, yani saldırı lehine kayar. Fazla dışlamanın bedeli yalnız
        /// "ölçemedik"tir; az dışlamanın bedeli yanlış bir sayıdır.</para>
        /// </summary>
        private static Rect FaceBoxFrom(float[] lm, double interocularDistance)
        {
            double cx = (lm[0] + lm[2]) / 2.0;
            double cy = (lm[1] + lm[3]) / 2.0 + 0.5 * interocularDistance;
            double halfW = 1.5 * interocularDistance;
            double halfH = 1.9 * interocularDistance;

            return new Rect(
                (int)(cx - halfW), (int)(cy - halfH),
                (int)(2 * halfW), (int)(2 * halfH));
        }

    }
}
