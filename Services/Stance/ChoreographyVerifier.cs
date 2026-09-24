using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using VerifyBlind.Core.Models;
using VerifyBlind.Enclave.Services.FaceAlignment;
using VerifyBlind.Enclave.Services.Vision;

namespace VerifyBlind.Enclave.Services.Stance
{
    /// <summary>
    /// Duruş + olay kanıtını ÖLÇER. Kapı kararlarını <see cref="EnclaveService"/> verir.
    ///
    /// <para><b>Asıl kazanç: her şey AYNI karelerden.</b> Eskiden jestler istemcide karara
    /// bağlanıyor, benzerlik "en iyi" seçilen bir kareden, parallaks ayrı dört kareden
    /// ölçülüyordu — üçü üç ayrı kaynaktan gelebilirdi. Burada parallaksı ölçülen duruş
    /// karelerinin HER BİRİNDE kart sahibinin yüzü aranır: derinliği gerçek bir kafa, kimliği
    /// başka bir kaynak sağlayamaz.</para>
    ///
    /// <para><b>Kapılar</b> (reddeden): yapı bozuk · parallaks düz ya da ölçülemedi · kimlik
    /// tutmuyor. <b>Ölçüm</b> (reddetmeyen): konum uyumu, duruş titreşimi, olay özellikleri,
    /// kontur oranı. Eşikleri meşru dağılım görülmeden konmayacak — p_live'da bu sırayı
    /// atlayıp meşru kullanıcıyı reddettik.</para>
    /// </summary>
    public interface IChoreographyVerifier
    {
        /// <param name="idPhotoBytes">
        /// DG2'den çıkarılmış kimlik fotoğrafı (Passive Auth'la doğrulanmış). Null ise kimlik
        /// ölçülmez — çağıran bunu kapıdan geçmiş SAYMAMALI.
        /// </param>
        PlanarityOutcome Measure(ChoreographyProof proof, Choreography demanded, byte[]? idPhotoBytes);

        /// <summary>
        /// Erken önizleme: yakın çıpa + ilk uzak durak karelerinde register'daki parallaks
        /// ölçümünün aynısı. BİLGİ verir, karar vermez.
        /// </summary>
        ParallaxPreviewResult Preview(IReadOnlyList<string> frames);

        /// <summary>Son ölçümün çift-başına P listesi — teşhis metnine girer.</summary>
        string LastPairDetail { get; }
    }

    /// <inheritdoc cref="IChoreographyVerifier"/>
    public sealed class ChoreographyVerifier : IChoreographyVerifier
    {
        public const string StatusMeasured = "measured";
        public const string StatusInvalid = "invalid";

        /// <summary>Durak başına en fazla duruş karesi: başı ve sonu.</summary>
        public const int MaxHoldPerStop = 2;

        /// <summary>Tek karenin en büyük boyutu — şişirilmiş yük koruması (parallaksla aynı).</summary>
        private const int MaxFrameBytes = 400_000;

        /// <summary>
        /// Durağın hedef yüz/kadraj oranı — istemcinin dayattığı değerlerle aynı. Enclave bu
        /// sayılara GÜVENMEZ; yalnız duraklar arası istenen ÖLÇEK DEĞİŞİMİNİ türetmek için
        /// kullanır (ör. uzak→yakın 2,0×).
        /// </summary>
        public static double TargetFraction(StancePosition position) => position switch
        {
            StancePosition.Far => 0.31,
            StancePosition.Mid => 0.31 * Math.Sqrt(2.0),
            _ => 0.62,
        };

        private readonly IBiometricService _biometric;
        private readonly PlanarityMeasurementService _planarity;

        public string LastPairDetail => _planarity.LastPairDetail;

        public ChoreographyVerifier(IBiometricService biometric)
        {
            _biometric = biometric;
            _planarity = new PlanarityMeasurementService(biometric);
        }

        /// <summary>İz kaydının tavanı (istemcininki 3500).</summary>
        public const int MaxTraceChars = 4000;

        internal static string? SanitizeTrace(string? trace)
        {
            if (string.IsNullOrEmpty(trace)) return null;
            var chars = trace.Length > MaxTraceChars ? trace[..MaxTraceChars] : trace;
            var sb = new System.Text.StringBuilder(chars.Length);
            foreach (char c in chars)
                sb.Append(c >= 0x20 && c < 0x7F ? c : '?');
            return sb.ToString();
        }

        private sealed class Frame
        {
            public required byte[] Bytes { get; init; }
            public FaceObservation? Face { get; init; }
            public double? Interocular { get; init; }
            public bool HasFace => Face != null && Interocular is > 0;
        }

        public PlanarityOutcome Measure(ChoreographyProof proof, Choreography demanded, byte[]? idPhotoBytes)
        {
            var clock = Stopwatch.StartNew();
            var result = new ChoreographyOutcome
            {
                Demanded = ChoreographyGenerator.Describe(demanded),
                Resets = proof.Resets,
                WrongEvents = proof.WrongEvents,
                ElapsedMs = proof.ElapsedMs,
                BgTextureNear = proof.BgTextureNear,
                TrackingChanges = proof.TrackingChanges,
                Redos = proof.Redos,
                // İstemci metni: uzunluk sınırlı, kontrol karakterleri ayıklanır — ölçüm satırını
                // şişirmesin, JSON'u bozmasın.
                Trace = SanitizeTrace(proof.Trace),
            };
            var outcome = new PlanarityOutcome
            {
                BgTexture = proof.BgTexture,
                ElapsedMs = proof.ElapsedMs,
                Choreography = result,
            };

            // ── 1. YAPI ─────────────────────────────────────────────────────────────
            // Meşru istemci diziyi TAMAMLAMADAN gönderemez. Eksik durak, fazla kare ya da
            // çözülemeyen kare ya bizim bir hatamızdır ya kurcalamadır; ikisinde de ölçülen
            // şey istenen dizi değildir.
            string? invalid = ValidateStructure(proof, demanded);
            if (invalid != null)
                return Invalid(outcome, result, invalid, clock);

            var stops = new List<(List<Frame> hold, List<Frame> events)>(proof.Stops.Count);
            foreach (var stop in proof.Stops)
            {
                var hold = new List<Frame>(stop.Hold.Count);
                foreach (var b64 in stop.Hold)
                {
                    var frame = Analyze(b64);
                    if (frame == null) return Invalid(outcome, result, "frame", clock);
                    hold.Add(frame);
                }
                var events = new List<Frame>(stop.Event.Count);
                foreach (var b64 in stop.Event)
                {
                    var frame = Analyze(b64);
                    if (frame == null) return Invalid(outcome, result, "frame", clock);
                    events.Add(frame);
                }
                stops.Add((hold, events));
            }

            result.Frames = stops.Sum(s => s.hold.Count + s.events.Count);
            result.Faces = stops.Sum(s => s.hold.Count(f => f.HasFace) + s.events.Count(f => f.HasFace));

            // Her durağın ölçüm karesi: yüzü bulunan İLK duruş karesi. Parallaks da kimlik de
            // bu karelerden — ikisinin aynı kareye bakması tasarımın ta kendisi.
            var anchor = stops.Select(s => s.hold.FirstOrDefault(f => f.HasFace)).ToList();

            // ── 2. PARALLAKS (katı kip) ─────────────────────────────────────────────
            MeasureParallax(outcome, proof, demanded, anchor);

            // ── 3. KİMLİK ───────────────────────────────────────────────────────────
            MeasureIdentity(result, stops, anchor, idPhotoBytes);

            // ── 4-7. ÖLÇÜMLER ───────────────────────────────────────────────────────
            MeasurePositions(result, demanded, anchor);
            MeasureHolds(result, stops);
            MeasureContour(result, demanded, stops);
            MeasureEvents(result, demanded, stops);

            result.Status = StatusMeasured;
            result.CostMs = (int)clock.ElapsedMilliseconds;
            return outcome;
        }

        /// <summary>Önizlemede işlenecek en fazla kare — her kare bir YuNet çıkarımı.</summary>
        public const int MaxPreviewFrames = 3;

        /// <inheritdoc/>
        public ParallaxPreviewResult Preview(IReadOnlyList<string> frames)
        {
            var clock = Stopwatch.StartNew();
            var result = new ParallaxPreviewResult();

            var analyzed = frames.Take(MaxPreviewFrames)
                .Select(Analyze)
                .Where(f => f is { HasFace: true })
                .Select(f => f!)
                .OrderBy(f => f.Interocular)   // uzaktan yakına
                .ToList();

            if (analyzed.Count >= 2)
            {
                var interocular = analyzed.Select(f => f.Interocular!.Value).ToList();
                var faceBox = analyzed.Select(f => PlanarityMeasurementService.FaceBoxFrom(f.Face!.Landmarks, f.Interocular!.Value)).ToList();
                var gray = analyzed.Select(f => GrayDecoder.Decode(f.Bytes)).ToList();

                // Register'daki katı ölçümle AYNI kurallar: dar çift P'ye girmez, en geniş tutan
                // çift uzak↔yakın olmalı. Farklı kural önizlemeyi register'dan ayırır ve kullanıcı
                // "önizleme geçti ama kayıt reddedildi" durumuna düşer.
                var parallax = PlanarityMeasurementService.MeasureParallax(gray, faceBox, interocular,
                    minPairSpan: PlanarityMeasurementService.MinStrictPairSpan);
                result.P = parallax.P;
                result.Span = parallax.Span;
                result.Inliers = parallax.Inliers;

                if (parallax.P is { } p && p < PlanarityMeasurementService.MinParallaxP)
                    result.Status = ParallaxPreviewStatuses.Flat;
                else if (parallax.P is null || parallax.Span is not { } s ||
                         s < PlanarityMeasurementService.MinStrictWidestSpan)
                    result.Status = ParallaxPreviewStatuses.Unmeasured;
                else
                    result.Status = ParallaxPreviewStatuses.Ok;
            }

            result.CostMs = (int)clock.ElapsedMilliseconds;
            return result;
        }

        private static PlanarityOutcome Invalid(PlanarityOutcome outcome, ChoreographyOutcome result,
            string reason, Stopwatch clock)
        {
            result.Status = StatusInvalid;
            result.InvalidReason = reason;
            result.CostMs = (int)clock.ElapsedMilliseconds;
            outcome.Status = PlanarityStatuses.Unmeasured;
            return outcome;
        }

        /// <summary>Yapı kuralları; bozuksa sabit kümeden bir sebep, sağlamsa null.</summary>
        internal static string? ValidateStructure(ChoreographyProof proof, Choreography demanded)
        {
            if (proof.Version != ChoreographyGenerator.Version) return "version";
            if (proof.Stops.Count != demanded.Stops.Count) return "stops";

            for (int i = 0; i < demanded.Stops.Count; i++)
            {
                var sent = proof.Stops[i];
                if (sent.Hold.Count is 0 or > MaxHoldPerStop) return "hold";

                int required = demanded.Stops[i].Event switch
                {
                    StanceEvent.None => 0,
                    StanceEvent.DoubleBlink => 2,
                    _ => 1,
                };
                // Tam olarak istenen sayı: olaysız durakta olay karesi de bozuk yapıdır —
                // enclave'in ölçmediği, yükü sessizce büyüten kare.
                if (sent.Event.Count != required) return "event";
            }
            return null;
        }

        private Frame? Analyze(string b64)
        {
            if (string.IsNullOrEmpty(b64)) return null;
            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); }
            catch (FormatException) { return null; }
            if (bytes.Length == 0 || bytes.Length > MaxFrameBytes) return null;

            var face = _biometric.DetectFace(bytes);
            return new Frame
            {
                Bytes = bytes,
                Face = face,
                Interocular = face is null ? null : PlanarityProbe.Interocular(face.Landmarks),
            };
        }

        /// <summary>
        /// Parallaksı durakların ölçüm karelerinden hesaplar — kareler İSTENEN mesafeye göre
        /// uzaktan yakına sıralanır (aynı mesafedekiler dizi sırasıyla).
        ///
        /// <para>Sıra istenenden alınıyor, ölçülenden değil: <see cref="PlanarityMeasurementService"/>
        /// zaten TÜM çiftleri deneyip yüz ölçeğine göre sıralıyor; buradaki sıra yalnız
        /// "açıklık = son/ilk" teşhis sayısını anlamlı kılar.</para>
        /// </summary>
        private void MeasureParallax(PlanarityOutcome outcome, ChoreographyProof proof,
            Choreography demanded, List<Frame?> anchor)
        {
            var order = Enumerable.Range(0, demanded.Stops.Count)
                .OrderBy(i => (int)demanded.Stops[i].Position)
                .ThenBy(i => i);

            var interocular = new List<double>();
            var gray = new List<GrayImage?>();
            var faceBox = new List<Rect>();
            foreach (int i in order)
            {
                if (anchor[i] is not { } f) continue;
                double d = f.Interocular!.Value;
                interocular.Add(d);
                faceBox.Add(PlanarityMeasurementService.FaceBoxFrom(f.Face!.Landmarks, d));
                gray.Add(GrayDecoder.Decode(f.Bytes));
            }

            _planarity.Evaluate(outcome, interocular, gray, faceBox, proof.BgTexture,
                framesSent: demanded.Stops.Count, complete: true, strict: true);
            outcome.Choreography!.ParallaxPairs = _planarity.LastPairCount;
        }

        /// <summary>
        /// Her durağın ölçüm karesinin çip fotoğrafına benzerliği (KAPI) ve olay karelerinin
        /// benzerliği (ÖLÇÜM).
        ///
        /// <para>⚠️ Yüzü bulunamayan durak 0 sayılır, atlanmaz: saldırganın kimliği tutmayacak
        /// durağı "yüz yok" karesiyle doldurması kapıyı atlatmamalı. Meşru akışta her durakta
        /// yüz var — istemci yüz görmeden duruşu kabul etmiyor.</para>
        /// </summary>
        private void MeasureIdentity(ChoreographyOutcome result,
            List<(List<Frame> hold, List<Frame> events)> stops, List<Frame?> anchor, byte[]? idPhotoBytes)
        {
            if (idPhotoBytes == null || !_biometric.IsModelLoaded) return;

            float[] reference;
            try { reference = _biometric.ComputeEmbedding(idPhotoBytes); }
            catch (Exception ex)
            {
                Console.WriteLine($"[Choreography] Kimlik referansı çıkarılamadı: {ex.GetType().Name}");
                return;
            }

            double Similarity(Frame? f)
            {
                if (f is not { HasFace: true }) return 0;
                try { return Math.Round(_biometric.CosineSimilarity(reference, _biometric.ComputeEmbedding(f.Bytes, f.Face!.Landmarks)), 4); }
                catch (Exception) { return 0; }
            }

            result.Identity = anchor.Select(Similarity).ToList();
            result.IdentityMin = result.Identity.Count > 0 ? result.Identity.Min() : null;

            var eventSims = stops.SelectMany(s => s.events).Select(Similarity).ToList();
            if (eventSims.Count > 0) result.EventIdentity = eventSims;
        }

        /// <summary>
        /// Duraklar arası ölçek uyumu: ardışık iki durakta ölçülen ölçek değişimi ile istenen
        /// değişimin log farkı. En büyüğü kaydedilir.
        ///
        /// <para>Mutlak konum değil DEĞİŞİM ölçülüyor: kolun uzunluğu, kameranın açısı kişiden
        /// kişiye değişir; "uzaktan yakına 2 kat büyüdü" ise herkeste aynı olmalı.</para>
        /// </summary>
        private static void MeasurePositions(ChoreographyOutcome result,
            Choreography demanded, List<Frame?> anchor)
        {
            var scales = anchor.Select(f => f?.Interocular).ToList();
            var measured = scales.Where(s => s is > 0).Select(s => s!.Value).ToList();
            if (measured.Count == 0) return;

            double min = measured.Min();
            result.StopScales = scales.Select(s => s is > 0 ? Math.Round(s.Value / min, 3) : 0).ToList();

            double? worst = null;
            for (int i = 0; i + 1 < scales.Count; i++)
            {
                if (scales[i] is not > 0 || scales[i + 1] is not > 0) continue;
                double measuredChange = scales[i + 1]!.Value / scales[i]!.Value;
                double demandedChange = TargetFraction(demanded.Stops[i + 1].Position) /
                                        TargetFraction(demanded.Stops[i].Position);
                double err = Math.Abs(Math.Log(measuredChange / demandedChange));
                worst = worst is null ? err : Math.Max(worst.Value, err);
            }
            if (worst is { } w) result.PositionErrMax = Math.Round(w, 4);
        }

        /// <summary>
        /// Duruş içi hareket: aynı durağın iki duruş karesi arasındaki ortalama piksel farkı ve
        /// ölçek kayması.
        ///
        /// <para>Çift taraflı tolerans fikrinin ÖLÇÜSÜ: hareket bir tavanın altında kalmalı (duruş)
        /// ama bir tabanın da üstünde olmalı (donmuş kare değil). Duraklatılmış videoda iki kare
        /// sıkıştırma gürültüsü kadar farklıdır; elde tutulan telefon her zaman titrer.</para>
        /// </summary>
        private static void MeasureHolds(ChoreographyOutcome result,
            List<(List<Frame> hold, List<Frame> events)> stops)
        {
            double? motionMin = null, scaleDevMax = null;
            foreach (var (hold, _) in stops)
            {
                if (hold.Count < 2) continue;

                if (hold[0].Interocular is > 0 && hold[1].Interocular is > 0)
                {
                    double dev = Math.Abs(Math.Log(hold[1].Interocular!.Value / hold[0].Interocular!.Value));
                    scaleDevMax = scaleDevMax is null ? dev : Math.Max(scaleDevMax.Value, dev);
                }

                var a = GrayDecoder.Decode(hold[0].Bytes);
                var b = GrayDecoder.Decode(hold[1].Bytes);
                if (a is not { } ga || b is not { } gb) continue;
                if (ga.Width != gb.Width || ga.Height != gb.Height) continue;

                double motion = MeanAbsDiff(ga.Pixels, gb.Pixels);
                motionMin = motionMin is null ? motion : Math.Min(motionMin.Value, motion);
            }
            if (motionMin is { } m) result.HoldMotionMin = Math.Round(m, 3);
            if (scaleDevMax is { } d) result.HoldScaleDevMax = Math.Round(d, 4);
        }

        internal static double MeanAbsDiff(byte[] a, byte[] b)
        {
            long sum = 0;
            int n = Math.Min(a.Length, b.Length);
            for (int i = 0; i < n; i++) sum += Math.Abs(a[i] - b[i]);
            return n == 0 ? 0 : (double)sum / n;
        }

        /// <summary>
        /// Kontur oranı — yüz kutusu genişliği / göz-arası, yakın duraklarda uzak duraklara bölünür.
        /// Gerekçe <see cref="ChoreographyOutcome.ContourRatio"/>.
        /// </summary>
        private static void MeasureContour(ChoreographyOutcome result,
            Choreography demanded, List<(List<Frame> hold, List<Frame> events)> stops)
        {
            var far = new List<double>();
            var near = new List<double>();
            for (int i = 0; i < stops.Count; i++)
            {
                var position = demanded.Stops[i].Position;
                if (position == StancePosition.Mid) continue;
                foreach (var f in stops[i].hold)
                {
                    if (!f.HasFace) continue;
                    double c = f.Face!.BoxW / f.Interocular!.Value;
                    (position == StancePosition.Far ? far : near).Add(c);
                }
            }
            if (far.Count > 0) result.ContourFar = Math.Round(Median(far), 4);
            if (near.Count > 0) result.ContourNear = Math.Round(Median(near), 4);
            if (result.ContourFar is > 0 && result.ContourNear is { } n)
                result.ContourRatio = Math.Round(n / result.ContourFar.Value, 4);
        }

        /// <summary>
        /// Her olay karesinde üç özellik, aynı durağın nötr duruş karesine göre.
        /// Gerekçe <see cref="EventMeasurement"/>.
        /// </summary>
        private static void MeasureEvents(ChoreographyOutcome result,
            Choreography demanded, List<(List<Frame> hold, List<Frame> events)> stops)
        {
            var list = new List<EventMeasurement>();
            for (int i = 0; i < stops.Count; i++)
            {
                var ev = demanded.Stops[i].Event;
                if (ev == StanceEvent.None) continue;

                var neutral = stops[i].hold.FirstOrDefault(f => f.HasFace);
                byte[]? neutralLuma = neutral is null ? null : EventFeatures.AlignedLuma(neutral.Bytes, neutral.Face!.Landmarks);
                double? neutralEye = neutralLuma is null ? null : EventFeatures.EyeContrast(neutralLuma);
                double? neutralDark = neutralLuma is null ? null : EventFeatures.MouthDarkFraction(neutralLuma);
                double? neutralWidth = neutral is null ? null : EventFeatures.MouthWidthRatio(neutral.Face!.Landmarks);

                foreach (var f in stops[i].events)
                {
                    var m = new EventMeasurement { Stop = i, Type = ChoreographyGenerator.EventName(ev) };
                    if (f.HasFace)
                    {
                        var luma = EventFeatures.AlignedLuma(f.Bytes, f.Face!.Landmarks);
                        if (luma != null && neutralEye is > 0)
                            m.EyeClosure = Math.Round(1.0 - EventFeatures.EyeContrast(luma) / neutralEye.Value, 4);
                        if (luma != null && neutralDark is { } nd)
                            m.MouthDark = Math.Round(EventFeatures.MouthDarkFraction(luma) - nd, 4);
                        if (neutralWidth is > 0 && EventFeatures.MouthWidthRatio(f.Face!.Landmarks) is { } w)
                            m.MouthWiden = Math.Round(w / neutralWidth.Value - 1.0, 4);
                    }
                    list.Add(m);
                }
            }
            if (list.Count > 0) result.Events = list;
        }

        private static double Median(List<double> values)
        {
            var sorted = values.OrderBy(v => v).ToList();
            int n = sorted.Count;
            return n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
        }
    }
}
