using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

namespace VerifyBlind.Enclave.Services.FaceAlignment
{
    /// <summary>
    /// YuNet 5-nokta yüz hizalama: tespit → ArcFace kanonik şablonuna similarity-transform
    /// warp (112x112). w600k_r50 bu hizalamayla eğitildi; hizalama olmadan center-crop FRR'yi
    /// çok yükseltir (LFW: ~%46 → ~%1.7). YuNet girdisi SABİT 640x640 (onnxruntime reshape
    /// yapmaz) → letterbox + ölçek geri-haritalama. Yüz bulunamazsa merkez-kare kırpmaya düşer.
    /// </summary>
    public sealed partial class FaceAligner : IDisposable
    {
        public const int OutputSize = 112;
        private const int InputSize = 640;
        private const float ScoreThreshold = 0.6f;
        private const float NmsThreshold = 0.3f;

        // ArcFace kanonik 5-nokta şablonu (112x112): sağ göz, sol göz, burun, sağ ağız, sol ağız.
        private static readonly float[] ArcfaceDst =
        {
            38.2946f, 51.6963f, 73.5318f, 51.5014f, 56.0252f, 71.7366f,
            41.5493f, 92.3655f, 70.7299f, 92.2041f
        };

        private readonly InferenceSession? _session;
        private readonly string _inputName = "input";
        private readonly bool _isLoaded;

        public bool IsLoaded => _isLoaded;

        public FaceAligner()
        {
            var modelPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models", "yunet.onnx");
            try
            {
                if (!File.Exists(modelPath))
                {
                    Console.WriteLine($"[FaceAligner] YuNet modeli bulunamadı: {modelPath} — hizalama merkez-kırpmaya düşecek.");
                    return;
                }
                _session = new InferenceSession(modelPath, new Microsoft.ML.OnnxRuntime.SessionOptions());
                _inputName = _session.InputMetadata.Keys.First();
                _isLoaded = true;
                Console.WriteLine($"[FaceAligner] YuNet yüklendi (girdi: {_inputName}, {InputSize}x{InputSize}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FaceAligner] Model yükleme hatası: {ex.Message} — merkez-kırpmaya düşülecek.");
            }
        }

        /// <summary>
        /// Görüntüyü hizalanmış 112x112 Rgb24'e dönüştürür. Yüz tespit edilemezse (veya model
        /// yoksa) merkez-kare kırpmaya düşer — eşik eşleşmeyi yine korur, meşru kullanıcı reddi
        /// yumuşatılır. Çağıran dönen görüntüyü dispose etmeli.
        /// </summary>
        public Image<Rgb24> Align(Image<Rgb24> source)
        {
            float[]? landmarks = _isLoaded ? DetectBestLandmarks(source) : null;
            if (landmarks == null)
            {
                Console.WriteLine("[FaceAligner] Yüz bulunamadı — merkez-kare kırpmaya düşülüyor.");
                return CenterCrop(source, OutputSize);
            }

            float[] m = Umeyama.SimilarityTransform(landmarks, ArcfaceDst);
            float[] inv = InvertAffine(m);
            return WarpAffineBilinear(source, inv, OutputSize, OutputSize);
        }

        /// <summary>
        /// Kaynağı 640x640'a letterbox'lar, YuNet'i çalıştırır, 3-stride decode + NMS yapar,
        /// en büyük yüzün 5 landmark'ını ORİJİNAL koordinatlara çevirir. Yüz yoksa null.
        /// </summary>
        private float[]? DetectBestLandmarks(Image<Rgb24> source)
        {
            if (_session == null) return null;

            int sw = source.Width, sh = source.Height;
            float scale = (float)InputSize / Math.Max(sw, sh);
            int nw = Math.Max(1, (int)Math.Round(sw * scale));
            int nh = Math.Max(1, (int)Math.Round(sh * scale));

            var input = new DenseTensor<float>(new[] { 1, 3, InputSize, InputSize });
            using (var canvas = new Image<Rgb24>(InputSize, InputSize, Color.Black))
            using (var resized = source.Clone(c => c.Resize(new ResizeOptions
            {
                Size = new Size(nw, nh),
                Mode = ResizeMode.Stretch,
                Sampler = KnownResamplers.Triangle    // bilinear — cv2 INTER_LINEAR ile en yakın
            })))
            {
                canvas.Mutate(c => c.DrawImage(resized, new Point(0, 0), 1f));
                // YuNet girdisi BGR ham [0,255] (OpenCV blobFromImage, swapRB=false ile aynı).
                canvas.ProcessPixelRows(acc =>
                {
                    for (int y = 0; y < InputSize; y++)
                    {
                        var row = acc.GetRowSpan(y);
                        for (int x = 0; x < InputSize; x++)
                        {
                            var p = row[x];
                            input[0, 0, y, x] = p.B;
                            input[0, 1, y, x] = p.G;
                            input[0, 2, y, x] = p.R;
                        }
                    }
                });
            }

            Dictionary<string, float[]> outs;
            using (var results = _session.Run(new[] { NamedOnnxValue.CreateFromTensor(_inputName, input) }))
            {
                outs = results.ToDictionary(r => r.Name, r => r.AsTensor<float>().ToArray());
            }

            var all = new List<FaceDetection>();
            foreach (int s in YunetDecoder.Strides)
            {
                all.AddRange(YunetDecoder.DecodeStride(
                    outs[$"cls_{s}"], outs[$"obj_{s}"], outs[$"bbox_{s}"], outs[$"kps_{s}"],
                    s, InputSize, ScoreThreshold));
            }

            FaceDetection? best = YunetDecoder.SelectBestFace(all, NmsThreshold);
            if (best == null) return null;

            // 640-canvas → orijinal koordinatlar (paste sol-üstte, ofset yok).
            var lmk = new float[10];
            for (int i = 0; i < 10; i++) lmk[i] = best.Landmarks[i] / scale;
            return lmk;
        }

        /// <summary>2x3 afin matrisin tersini döndürür ([a,b,tx,c,d,ty]).</summary>
        public static float[] InvertAffine(float[] m)
        {
            double a = m[0], b = m[1], c = m[3], d = m[4];
            double det = a * d - b * c;
            if (Math.Abs(det) < 1e-12)
                throw new ArgumentException("Afin matris tekil — tersi alınamaz.");

            double ia = d / det, ib = -b / det, ic = -c / det, id = a / det;
            double tx = m[2], ty = m[5];
            double itx = -(ia * tx + ib * ty);
            double ity = -(ic * tx + id * ty);

            return new[] { (float)ia, (float)ib, (float)itx, (float)ic, (float)id, (float)ity };
        }

        /// <summary>
        /// invAffine: ÇIKTI koord → KAYNAK koord (sampling yönü). Çıktının her pikselini
        /// kaynaktan bilinear örnekler; kaynak dışı komşular 0 (cv2 BORDER_CONSTANT=0 ile aynı).
        /// </summary>
        public static Image<Rgb24> WarpAffineBilinear(Image<Rgb24> src, float[] invAffine, int outW, int outH)
        {
            int sw = src.Width, sh = src.Height;
            var sp = new Rgb24[sw * sh];
            src.CopyPixelDataTo(sp);

            var dst = new Image<Rgb24>(outW, outH);
            float ia = invAffine[0], ib = invAffine[1], ic = invAffine[2];
            float id = invAffine[3], ie = invAffine[4], iff = invAffine[5];

            dst.ProcessPixelRows(acc =>
            {
                for (int y = 0; y < outH; y++)
                {
                    var row = acc.GetRowSpan(y);
                    for (int x = 0; x < outW; x++)
                    {
                        float fx = ia * x + ib * y + ic;
                        float fy = id * x + ie * y + iff;
                        row[x] = SampleBilinear(sp, sw, sh, fx, fy);
                    }
                }
            });
            return dst;
        }

        private static Rgb24 SampleBilinear(Rgb24[] sp, int sw, int sh, float fx, float fy)
        {
            int x0 = (int)MathF.Floor(fx), y0 = (int)MathF.Floor(fy);
            int x1 = x0 + 1, y1 = y0 + 1;
            float wx = fx - x0, wy = fy - y0;

            // Komşu tamamen görüntü dışındaysa kenar yok → tüm geçerlilik kontrolü ile 0-pad.
            float r = 0, g = 0, b = 0;
            Accumulate(sp, sw, sh, x0, y0, (1 - wx) * (1 - wy), ref r, ref g, ref b);
            Accumulate(sp, sw, sh, x1, y0, wx * (1 - wy), ref r, ref g, ref b);
            Accumulate(sp, sw, sh, x0, y1, (1 - wx) * wy, ref r, ref g, ref b);
            Accumulate(sp, sw, sh, x1, y1, wx * wy, ref r, ref g, ref b);

            return new Rgb24(ToByte(r), ToByte(g), ToByte(b));
        }

        private static void Accumulate(Rgb24[] sp, int sw, int sh, int x, int y, float w,
                                       ref float r, ref float g, ref float b)
        {
            if (w == 0f || x < 0 || y < 0 || x >= sw || y >= sh) return;
            var p = sp[y * sw + x];
            r += p.R * w; g += p.G * w; b += p.B * w;
        }

        private static byte ToByte(float v)
        {
            int i = (int)(v + 0.5f);
            return (byte)(i < 0 ? 0 : (i > 255 ? 255 : i));
        }

        /// <summary>
        /// Yüz tespit edilemediğinde fallback: merkez-kare kırpma + portrede üst-bias (eski
        /// SmartFaceCrop davranışı). Hizalanmış değil — düşük skor verir ama meşru kullanıcı
        /// yeniden deneyebilir; eşik eşleşmeyi korur.
        /// </summary>
        private static Image<Rgb24> CenterCrop(Image<Rgb24> source, int size)
        {
            var img = source.Clone();
            if (img.Width == size && img.Height == size)
                return img;

            int side = Math.Min(img.Width, img.Height);
            int left = (img.Width - side) / 2;
            int top = img.Height > img.Width ? (int)((img.Height - side) * 0.2f) : (img.Height - side) / 2;
            img.Mutate(x => x
                .Crop(new Rectangle(left, top, side, side))
                .Resize(new ResizeOptions { Size = new Size(size, size), Sampler = KnownResamplers.Lanczos3 }));
            return img;
        }

        public void Dispose() => _session?.Dispose();
    }
}
