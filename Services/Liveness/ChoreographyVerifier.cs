using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services.Liveness
{
    /// <summary>
    /// Olay dizisi kanıtını ÖLÇER. Kapı kararlarını <see cref="EnclaveService"/> verir.
    ///
    /// <para><b>Asıl kazanç: kimlik HAREKETİN karesinde.</b> Eskiden jestler yalnız istemcide
    /// karara bağlanıyor, benzerlik ise "en iyi" seçilen tek bir kareden ölçülüyordu — ikisi iki
    /// ayrı kaynaktan gelebilirdi (monitörde kart sahibinin fotoğrafı, hareket saldırganın
    /// yüzünde). Burada hem hareketlerin ARASINDAKİ nötr karelerde hem hareketin KENDİ karesinde
    /// kart sahibinin yüzü aranır.</para>
    ///
    /// <para><b>Kapılar</b> (reddeden): yapı bozuk · herhangi bir karede kimlik tutmuyor.
    /// <b>Ölçüm</b> (reddetmeyen): olay özellikleri. Sahadaki ilk koşularda göz kapanma ve ağız
    /// koyuluğu meşru harekette de sıfır ya da negatif çıkabildi; eşik konursa meşru kullanıcı
    /// reddedilir — p_live'da bu sırayı atlayıp tam bunu yaşadık.</para>
    /// </summary>
    public interface IChoreographyVerifier
    {
        /// <param name="idPhotoBytes">
        /// DG2'den çıkarılmış kimlik fotoğrafı (Passive Auth'la doğrulanmış). Null ise kimlik
        /// ölçülmez — çağıran bunu kapıdan geçmiş SAYMAMALI.
        /// </param>
        ChoreographyOutcome Measure(ChoreographyProof proof, Choreography demanded, byte[]? idPhotoBytes);
    }

    /// <inheritdoc cref="IChoreographyVerifier"/>
    public sealed class ChoreographyVerifier : IChoreographyVerifier
    {
        public const string StatusMeasured = "measured";
        public const string StatusInvalid = "invalid";

        /// <summary>Adım başına nötr kare: tam olarak bir.</summary>
        public const int NeutralPerStep = 1;

        /// <summary>Tek karenin en büyük boyutu — şişirilmiş yük koruması.</summary>
        private const int MaxFrameBytes = 400_000;

        /// <summary>İz kaydının tavanı (istemcininki 3500).</summary>
        public const int MaxTraceChars = 4000;

        private readonly IBiometricService _biometric;

        public ChoreographyVerifier(IBiometricService biometric) => _biometric = biometric;

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
            public bool HasFace => Face != null;
        }

        public ChoreographyOutcome Measure(ChoreographyProof proof, Choreography demanded, byte[]? idPhotoBytes)
        {
            var clock = Stopwatch.StartNew();
            var result = new ChoreographyOutcome
            {
                Demanded = ChoreographyGenerator.Describe(demanded),
                Resets = proof.Resets,
                WrongEvents = proof.WrongEvents,
                ElapsedMs = proof.ElapsedMs,
                TrackingChanges = proof.TrackingChanges,
                // İstemci metni: uzunluk sınırlı, kontrol karakterleri ayıklanır — ölçüm satırını
                // şişirmesin, JSON'u bozmasın.
                Trace = SanitizeTrace(proof.Trace),
            };

            // ── 1. YAPI ─────────────────────────────────────────────────────────────
            // Meşru istemci diziyi TAMAMLAMADAN gönderemez. Eksik adım, fazla kare ya da
            // çözülemeyen kare ya bizim bir hatamızdır ya kurcalamadır; ikisinde de ölçülen
            // şey istenen dizi değildir.
            string? invalid = ValidateStructure(proof, demanded);
            if (invalid != null)
                return Invalid(result, invalid, clock);

            var steps = new List<(Frame neutral, List<Frame> events)>(proof.Steps.Count);
            foreach (var step in proof.Steps)
            {
                var neutral = Analyze(step.Neutral[0]);
                if (neutral == null) return Invalid(result, "frame", clock);
                var events = new List<Frame>(step.Event.Count);
                foreach (var b64 in step.Event)
                {
                    var frame = Analyze(b64);
                    if (frame == null) return Invalid(result, "frame", clock);
                    events.Add(frame);
                }
                steps.Add((neutral, events));
            }

            result.Frames = steps.Sum(s => 1 + s.events.Count);
            result.Faces = steps.Sum(s => (s.neutral.HasFace ? 1 : 0) + s.events.Count(f => f.HasFace));

            // ── 2. KİMLİK ───────────────────────────────────────────────────────────
            MeasureIdentity(result, steps, idPhotoBytes);

            // ── 3. OLAYLAR (ölçüm) ──────────────────────────────────────────────────
            MeasureEvents(result, demanded, steps);

            result.Status = StatusMeasured;
            result.CostMs = (int)clock.ElapsedMilliseconds;
            return result;
        }

        private static ChoreographyOutcome Invalid(ChoreographyOutcome result, string reason, Stopwatch clock)
        {
            result.Status = StatusInvalid;
            result.InvalidReason = reason;
            result.CostMs = (int)clock.ElapsedMilliseconds;
            return result;
        }

        /// <summary>Yapı kuralları; bozuksa sabit kümeden bir sebep, sağlamsa null.</summary>
        internal static string? ValidateStructure(ChoreographyProof proof, Choreography demanded)
        {
            if (proof.Version != ChoreographyGenerator.Version) return "version";
            if (proof.Steps.Count != demanded.Events.Count) return "steps";

            for (int i = 0; i < demanded.Events.Count; i++)
            {
                var sent = proof.Steps[i];
                if (sent.Neutral.Count != NeutralPerStep) return "neutral";
                // Tam olarak istenen sayı: fazla olay karesi enclave'in ölçmediği, yükü sessizce
                // büyüten karedir.
                if (sent.Event.Count != ChoreographyGenerator.FramesFor(demanded.Events[i])) return "event";
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

            return new Frame { Bytes = bytes, Face = _biometric.DetectFace(bytes) };
        }

        /// <summary>
        /// Her adımın nötr karesinin ve her olay karesinin çip fotoğrafına benzerliği. Kapı
        /// ikisinin birleşiminin EN KÜÇÜĞÜNE bakar.
        ///
        /// <para>⚠️ Yüzü bulunamayan kare 0 sayılır, atlanmaz: saldırganın kimliği tutmayacak
        /// kareyi "yüz yok" karesiyle doldurması kapıyı atlatmamalı. Meşru akışta her karede yüz
        /// var — istemci yüz görmeden adımı ilerletmiyor.</para>
        /// </summary>
        private void MeasureIdentity(ChoreographyOutcome result,
            List<(Frame neutral, List<Frame> events)> steps, byte[]? idPhotoBytes)
        {
            if (idPhotoBytes == null || !_biometric.IsModelLoaded) return;

            float[] reference;
            try { reference = _biometric.ComputeEmbedding(idPhotoBytes); }
            catch (Exception ex)
            {
                Console.WriteLine($"[Choreography] Kimlik referansı çıkarılamadı: {ex.GetType().Name}");
                return;
            }

            double Similarity(Frame f)
            {
                if (!f.HasFace) return 0;
                try { return Math.Round(_biometric.CosineSimilarity(reference, _biometric.ComputeEmbedding(f.Bytes, f.Face!.Landmarks)), 4); }
                catch (Exception) { return 0; }
            }

            result.Identity = steps.Select(s => Similarity(s.neutral)).ToList();
            result.EventIdentity = steps.SelectMany(s => s.events).Select(Similarity).ToList();
            var all = result.Identity.Concat(result.EventIdentity).ToList();
            result.IdentityMin = all.Count > 0 ? all.Min() : null;
        }

        /// <summary>
        /// Her olay karesinde üç özellik, aynı adımın nötr karesine göre.
        /// Gerekçe <see cref="EventMeasurement"/>.
        /// </summary>
        private static void MeasureEvents(ChoreographyOutcome result,
            Choreography demanded, List<(Frame neutral, List<Frame> events)> steps)
        {
            var list = new List<EventMeasurement>();
            for (int i = 0; i < steps.Count; i++)
            {
                var neutral = steps[i].neutral;
                byte[]? neutralLuma = neutral.HasFace ? EventFeatures.AlignedLuma(neutral.Bytes, neutral.Face!.Landmarks) : null;
                double? neutralEye = neutralLuma is null ? null : EventFeatures.EyeContrast(neutralLuma);
                double? neutralDark = neutralLuma is null ? null : EventFeatures.MouthDarkFraction(neutralLuma);
                double? neutralWidth = neutral.HasFace ? EventFeatures.MouthWidthRatio(neutral.Face!.Landmarks) : null;

                foreach (var f in steps[i].events)
                {
                    var m = new EventMeasurement { Step = i, Type = ChoreographyGenerator.EventName(demanded.Events[i]) };
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
    }
}
