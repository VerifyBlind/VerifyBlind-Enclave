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
        /// B için denenecek EN FAZLA kare çifti. Tutanların HEPSİ kullanılır, ilk tutan değil.
        ///
        /// <para>Ölçüldü: gerçekçi bir sahnede çift başına ~175 ms (240×320), yüksek entropili
        /// bir karede ~830 ms (360×480). İkincisi yamalanmış bir istemcinin enclave CPU'sunu
        /// yakmak için kullanabileceği bir yüzey; çift sayısını sınırlamak onu sabitler.
        /// Medyan için dört çift zaten fazlasıyla yeterli.</para>
        /// </summary>
        private const int MaxPairAttempts = 6;

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

        /// <summary>
        /// 🔴 KAPI: normalize parallaks payı <c>P</c> bunun altındaysa yüzey DÜZ sayılır ve
        /// kayıt reddedilir. Parallaks hattının ilk ve tek reddi budur.
        ///
        /// <para><b>Kalibrasyon (2026-09-22, tek cihaz, tek ev):</b></para>
        /// <code>
        /// desteklenen meşru : 0,402  0,729  0,824  0,832
        /// yatak senaryosu   : 0,141  0,163  0,242  0,253   (DESTEKLENMİYOR, aşağıya bakın)
        /// ekran düzenekleri : −0,022  0,063
        /// </code>
        ///
        /// <para>0,30: sahte tarafa <b>0,24</b>, desteklenen en kötü meşru duruma (sırt
        /// kütüphanede, eşyalar 20 cm) <b>0,10</b> pay bırakıyor.</para>
        ///
        /// <para><b>Yatak senaryosu bilerek dışarıda</b> (kamera tavandan, sırtüstü): üç eksende
        /// birden sınırda — doku 15,4-16,8 (kapı 14,0), geniş çift hiç tutmuyor, P 0,14-0,25.
        /// Onu içeri almak eşiği 0,10'a indirmek ve saldırıya pay bırakmamak demekti. Kimlik
        /// doğrulamasında kullanıcıdan doğrulup arkasındaki yüzeyden uzaklaşmasını istemek
        /// meşru (kullanıcı kararı). ⚠️ Ama mesaj EYLEM BİLDİRMELİ — p_live'daki genel
        /// "canlılık doğrulanamadı" hatası tekrarlanmayacak.</para>
        ///
        /// <para>⚠️ <b>Yalnız ÖLÇÜLEBİLEN akış reddedilir.</b> P yoksa (dokusuz arka plan,
        /// yetersiz eşleşme) kapı çalışmaz: "ölçemedik" ile "sahte" ayrı şeyler ve düz duvarın
        /// önündeki meşru kullanıcı reddedilmemeli. Bu, saldırganın ölçümü bilerek imkânsız
        /// kılarak kapıyı atlamasına açık bir yüzey bırakır — bilinçli tercih; ölçülemeyen
        /// akışların oranı <c>planarity_status</c> dağılımından izlenecek.</para>
        ///
        /// <para>n = 10. Tek cihaz, tek ev. Geniş dağılım geldikçe yeniden bakılacak.</para>
        /// </summary>
        public const double MinParallaxP = 0.30;

        private readonly IBiometricService _biometric;

        /// <summary>Son ölçümün çift-başına P listesi — teşhis metnine eklenir.</summary>
        internal string LastPairDetail => _lastPairDetail;
        private string _lastPairDetail = "-";

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

            return Evaluate(outcome, interocular, gray, faceBox, proof.BgTexture,
                framesSent: proof.Frames.Count, complete: proof.Complete, strict: false);
        }

        /// <summary>
        /// 🔴 KATI KİPTE istenen en küçük açıklık (ölçümün yapıldığı çiftin yüz ölçeği).
        ///
        /// <para>P'nin gürültüsü açıklıkla ters orantılı: B'deki ±0,03'lük hata P'de
        /// ±0,03/(s−1) eder. s = 1,1'de ±0,3 — düz bir ekran şans eseri 0,30'u aşabilir.
        /// Saldırganın en ucuz kaçamağı tam budur: hareketi küçük tut, gürültü işini görsün.
        /// 1,25'te hata ±0,12; sahte bant 0'da kalır.</para>
        ///
        /// <para>Meşru kullanıcıya maliyeti yok: duruş dizisi uzak (0,31) ile yakın (0,62)
        /// arasında 2,0× açıklık dayatıyor. Yatak koşularında bile tutan en geniş çift 1,34-1,73.</para>
        /// </summary>
        public const double MinStrictSpan = 1.25;

        /// <summary>
        /// Önceden çözülmüş karelerden durumu ve parallaksı hesaplar. Kareler en uzaktan en
        /// yakına SIRALI.
        /// </summary>
        /// <param name="strict">
        /// Duruş kanıtı: "ölçemedik" de RED sebebidir (<see cref="PlanarityStatuses.Unmeasured"/>).
        /// Eski kanıtta ölçülemeyen akış geçer; gerekçe <see cref="PlanarityStatuses.Unmeasured"/>.
        /// </param>
        internal PlanarityOutcome Evaluate(
            PlanarityOutcome outcome, List<double> interocular, List<GrayImage?> gray,
            List<Rect> faceBox, double? bgTexture, int framesSent, bool complete, bool strict)
        {
            outcome.FarMeasured = interocular.Count;

            if (interocular.Count == 0)
            {
                outcome.Status = strict ? PlanarityStatuses.Unmeasured : PlanarityStatuses.NoFaceFar;
                return outcome;
            }

            // Kareler en uzaktan en yakına SIRALI geliyor → açıklık = son / ilk.
            // Bunu istemciden almıyoruz: açıklık sinyalin anlamını belirleyen sayı ve
            // istemcinin beyanı doğrulanamaz.
            double span = interocular[^1] / interocular[0];
            outcome.IedRatio = Math.Round(span, 4);

            var parallax = MeasureParallax(gray, faceBox, interocular);
            outcome.Delta = parallax.Ratio;
            outcome.NearResidual = parallax.P;
            outcome.FarResidual = parallax.Span;
            outcome.NearMeasured = parallax.Inliers;
            _lastPairDetail = parallax.PairDetail;

            // 🔴 SIRA ÖNEMLİ: P hesaplanabildiyse KAPI HER ŞEYDEN ÖNCE ÇALIŞIR.
            //
            // Önceki sürümde doku kontrolü öndeydi ve sahada şunu yaptı (2026-09-24, duvar dibi
            // koşusu): istemci doku 12,0 bildirdi → `no_texture` → kapı hiç çalışmadı → akış
            // GEÇTİ. Oysa aynı koşuda P = 0,109 ile HESAPLANMIŞTI, 23 uyumla. Yani ölçtük, sonra
            // "ölçemedik" diye etiketledik.
            //
            // İki sonucu vardı: (a) saldırgana düşük dokulu bir düzenekle kapıyı tamamen atlama
            // yolu; (b) fiziksel olarak AYNI durumun (sırt bir yüzeye dayalı) bazen geçip bazen
            // düşmesi — farkı belirleyen şey geometri değil, İSTEMCİNİN BİLDİRDİĞİ bir sayıydı.
            //
            // Ölçülebilirliğin doğru ölçütü bizim kendi uyum sayımız, istemcinin doku raporu
            // değil. Doku artık yalnız P HESAPLANAMADIĞINDA anlamlı: o zaman "neden ölçemedik"
            // sorusunu cevaplıyor.
            if (parallax.P is { } p && p < MinParallaxP)
                // Ölçtük ve DÜZ çıktı. Diğer tüm durumlardan farkı: bu bir RED sebebi.
                outcome.Status = PlanarityStatuses.FlatSurface;
            else if (strict && (parallax.P is null || parallax.Span is not { } s || s < MinStrictSpan))
                // Duruş kanıtında ölçülemeyen ya da yetersiz açıklıkla ölçülen akış GEÇMEZ.
                outcome.Status = PlanarityStatuses.Unmeasured;
            else if (interocular.Count < MinFrames)
                outcome.Status = PlanarityStatuses.NotEnoughFrames;
            else if (parallax.P is null && bgTexture is { } t && t < MinBackgroundTexture)
                // Ölçemedik VE sebebi belli: arka planda eşleştirilecek desen yok.
                outcome.Status = PlanarityStatuses.NoTexture;
            else if (span < 1.2)
                // Kullanıcı yeterince yaklaşmadı → sinyalin anlamı yok.
                outcome.Status = PlanarityStatuses.NotApproached;
            else
                outcome.Status = PlanarityStatuses.Measured;

            Console.WriteLine(
                $"[Parallax] durum={outcome.Status} kare={outcome.FarMeasured}/{framesSent} " +
                $"açıklık={span:F2} B={outcome.Delta?.ToString("F3") ?? "-"} " +
                $"P={outcome.NearResidual?.ToString("F3") ?? "-"} s={outcome.FarResidual?.ToString("F2") ?? "-"} uyum={outcome.NearMeasured} " +
                $"doku={bgTexture?.ToString("F1") ?? "-"} " +
                $"tam={complete}");

            return outcome;
        }

        /// <summary>B ölçümünün sonucu: oran, göreli arka plan derinliği ve dayandığı uyum sayısı.</summary>
        internal readonly record struct ParallaxResult(double? Ratio, double? P, double? Span, int Inliers, string PairDetail);

        /// <summary>
        /// PARALLAKS ÖLÇÜMÜ — <c>B = yüz ölçeği / arka plan ölçeği</c> ve ondan türetilen
        /// normalize pay <c>P</c>.
        ///
        /// <para>⚠️ "En geniş çift" <b>ilk↔son DEĞİL</b>, tüm çiftler arasında ölçeği en büyük
        /// olandır. Göz-arası ölçümleri tam monoton olmadığı için (kafa oynar, YuNet gürültüsü)
        /// aradaki bir çift daha geniş çıkabiliyor: sahada `[..]` dizisinde `son/ilk = 1,2618`
        /// iken kullanılan çift 1,2806 verdi. Bu yüzden <c>parallax_span</c>, <c>ied_ratio</c>'yu
        /// AŞABİLİR ve bu bir tutarsızlık değildir — B ile s aynı çiftten geldiği için P doğrudur.</para>
        ///
        /// <para>🔴 <b>EN GENİŞ ÇİFTTEN BAŞLANIR ve TUTAN ÇİFTLERİN HEPSİ KULLANILIR.</b>
        /// Fizik: yüz kameradan <i>N</i>, arka plan yüzden <i>g</i> geride, çiftin yüz ölçeği
        /// <i>s</i> iken <c>B = s(N+g)/(sN+g)</c>. Buradan çıkan sınır belirleyici:
        /// <b>B asla s'yi aşamaz.</b> Ardışık çiftlerde s ~1,27 olduğu için B de 1,27'nin
        /// altında kalıyordu; sahada ölçülen 1,19-1,21 o tavanın %95'iydi — sinyal zayıf değil,
        /// çift seçimiyle kırpılmıştı. En geniş çifte geçince aynı sahneler 1,64-1,66 verdi.</para>
        ///
        /// <para><b>Neden ilk tutan değil, hepsi:</b> yakın uçta yüz kutusu büyüdüğü için en
        /// geniş çift her zaman eşleşmiyor (2026-09-22: 2,72 açıklıklı koşuda geniş çift tuttu
        /// sanıldı, gerçekte 1,91'lik bir çifte düşülmüştü). Tutan çiftlerin hepsinden P
        /// hesaplayıp MEDYANINI almak, uyum sayısının düşük olduğu (14-29) bu aşamada tek bir
        /// çiftin gürültüsüne teslim olmayı engelliyor.</para>
        ///
        /// <para><b>Neden P, B değil:</b> <c>P = (B−1)/(s−1)</c> — düz yüzeyde 0, sonsuz uzak
        /// arka planda 1. B'nin aksine SINIRLI ve çiftten çifte kıyaslanabilir. Sahada meşru
        /// koşular 0,70-0,75, monitör düzeneği 0,03 verdi. Eşik buraya konacak.</para>
        ///
        /// <para>⚠️ <c>ied_ratio</c> körlemesine <i>s</i> sanılmamalı: en geniş çift tutmadığında
        /// gerçek s daha küçüktür. Bu yüzden kullanılan s AYRICA kaydediliyor.</para>
        ///
        /// <para>Hiçbir çift ölçülemezse boş döner: "ölçemedik", "sahte" DEĞİL.</para>
        /// </summary>
        internal static ParallaxResult MeasureParallax(
            List<GrayImage?> gray, List<Rect> faceBox, List<double> interocular)
        {
            var candidates = new List<(int i, int j, double faceScale)>();
            for (int i = 0; i < gray.Count; i++)
                for (int j = i + 1; j < gray.Count; j++)
                {
                    if (interocular[i] <= 0) continue;
                    if (gray[i] is null || gray[j] is null) continue;
                    candidates.Add((i, j, interocular[j] / interocular[i]));
                }

            candidates.Sort((x, y) => y.faceScale.CompareTo(x.faceScale));

            // Öznitelikler kare başına BİR KEZ çıkarılır. Altı çift denemesinde her kareyi
            // yeniden çıkarmak, çıkarma maliyeti eşleştirmeyle aynı mertebede olduğu için
            // ölçümü birkaç katına çıkarırdı.
            var features = new List<Feature>?[gray.Count];
            List<Feature> FeaturesOf(int k)
            {
                if (features[k] is { } cached) return cached;
                var img = gray[k]!.Value;
                var f = BackgroundScaleEstimator.ExtractFor(img.Pixels, img.Width, img.Height, faceBox[k]);
                features[k] = f;
                return f;
            }

            int attempts = 0;
            double? widestRatio = null, widestSpan = null;
            int widestInliers = 0;
            var normalized = new List<double>();

            foreach (var (i, j, faceScale) in candidates)
            {
                if (attempts >= MaxPairAttempts) break;
                if (faceScale <= 1.02) continue;   // ölçek farkı yoksa P'nin paydası sıfıra gider
                attempts++;

                var background = BackgroundScaleEstimator.Estimate(FeaturesOf(i), FeaturesOf(j));

                if (BackgroundScaleEstimator.ParallaxRatio(faceScale, background) is not { } ratio)
                    continue;

                // 🔴 B > s FİZİKSEL OLARAK İMKÂNSIZ (arka plan yüzden hızlı büyümüş demektir).
                // Böyle bir sonuç sahnenin katı olmadığını söyler — ekrandaki görüntü kendi
                // başına hareket ediyor olabilir. Sayıyı kaydetmek yerine o çifti atıyoruz.
                if (ratio >= faceScale) continue;

                normalized.Add((ratio - 1.0) / (faceScale - 1.0));

                // En geniş TUTAN çift, okunabilir B ve onun ölçeği olarak raporlanır. Liste
                // açıklığa göre sıralı olduğu için ilk tutan zaten en geniş olandır.
                if (widestRatio is null)
                {
                    widestRatio = Math.Round(ratio, 4);
                    widestSpan = Math.Round(faceScale, 4);
                    widestInliers = background!.Value.Inliers;
                }
            }

            if (normalized.Count == 0) return new ParallaxResult(null, null, null, 0, "-");

            // 🔴 Çift başına P'ler TEŞHİS KANALINA yazılır, Console'a DEĞİL.
            //
            // Enclave üretimde debug-mode olmadığı için konsolu dışarı bağlı değil ve
            // Console.WriteLine çıktısı hiçbir yere ulaşmıyor (debug-mode PCR0'ı sıfırlar,
            // uygulama onu zaten reddeder). İlk sürümde buraya Console.WriteLine yazmıştım ve
            // relay logunda hiç görünmedi — teşhis için eklenen satır sessizce ölüydü.
            // Dışarı çıkan tek kanal diag: onun metni yanıtta taşınıyor ve relay logluyor.
            string detail = string.Join(" · ", normalized.ConvertAll(v => v.ToString("F3")));

            normalized.Sort();
            double p = normalized.Count % 2 == 1
                ? normalized[normalized.Count / 2]
                : (normalized[normalized.Count / 2 - 1] + normalized[normalized.Count / 2]) / 2;

            return new ParallaxResult(widestRatio, Math.Round(p, 4), widestSpan, widestInliers, detail);
        }

        /// <summary>
        /// Beş YuNet noktasından kaba yüz kutusu — ORB'un DIŞLAYACAĞI bölge.
        ///
        /// <para>Cömert tutuluyor: kutuya sığmayan saç/çene arka plana karışırsa payda paya
        /// yaklaşır ve oran 1'e, yani saldırı lehine kayar. Fazla dışlamanın bedeli yalnız
        /// "ölçemedik"tir; az dışlamanın bedeli yanlış bir sayıdır.</para>
        /// </summary>
        internal static Rect FaceBoxFrom(float[] lm, double interocularDistance)
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
