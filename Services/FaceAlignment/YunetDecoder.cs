using System;
using System.Collections.Generic;
using System.Linq;

namespace VerifyBlind.Enclave.Services.FaceAlignment
{
    /// <summary>Tek bir YuNet yüz tespiti (640-canvas koordinatlarında).</summary>
    public sealed class FaceDetection
    {
        public float Score;
        public float X, Y, W, H;          // sol-üst köşe + genişlik/yükseklik
        public float[] Landmarks = new float[10];  // 5 nokta: x0,y0,...,x4,y4
        public float Area => W * H;
    }

    /// <summary>
    /// YuNet çıktısını (cls/obj/bbox/kps, stride 8/16/32) yüz tespitlerine çözer.
    /// Decode OpenCV FaceDetectorYN ile aynı; onnxruntime sabit 640x640 beslediğinden
    /// koordinatlar 640-canvas uzayındadır (FaceAligner letterbox ölçeğiyle geri çevirir).
    /// </summary>
    public static class YunetDecoder
    {
        public static readonly int[] Strides = { 8, 16, 32 };

        /// <summary>Tek stride'ı çöz: cls/obj [N], bbox [N*4], kps [N*10]. score=√(cls·obj).</summary>
        public static List<FaceDetection> DecodeStride(
            float[] cls, float[] obj, float[] bbox, float[] kps,
            int stride, int inputSize, float scoreThreshold)
        {
            int cols = inputSize / stride;
            int n = cls.Length;
            var result = new List<FaceDetection>();

            for (int idx = 0; idx < n; idx++)
            {
                float clsScore = Clamp01(cls[idx]);
                float objScore = Clamp01(obj[idx]);
                float score = MathF.Sqrt(clsScore * objScore);
                if (score < scoreThreshold)
                    continue;

                int c = idx % cols;
                int r = idx / cols;

                float cx = (c + bbox[idx * 4 + 0]) * stride;
                float cy = (r + bbox[idx * 4 + 1]) * stride;
                float w = MathF.Exp(bbox[idx * 4 + 2]) * stride;
                float h = MathF.Exp(bbox[idx * 4 + 3]) * stride;

                var det = new FaceDetection
                {
                    Score = score,
                    X = cx - w / 2f,
                    Y = cy - h / 2f,
                    W = w,
                    H = h,
                    Landmarks = new float[10]
                };
                for (int k = 0; k < 5; k++)
                {
                    det.Landmarks[2 * k] = (c + kps[idx * 10 + 2 * k]) * stride;
                    det.Landmarks[2 * k + 1] = (r + kps[idx * 10 + 2 * k + 1]) * stride;
                }
                result.Add(det);
            }
            return result;
        }

        /// <summary>Greedy NMS (skor azalan; IoU>threshold bastırılır).</summary>
        public static List<FaceDetection> Nms(List<FaceDetection> dets, float nmsThreshold)
        {
            var ordered = dets.OrderByDescending(d => d.Score).ToList();
            var kept = new List<FaceDetection>();
            var suppressed = new bool[ordered.Count];

            for (int i = 0; i < ordered.Count; i++)
            {
                if (suppressed[i]) continue;
                kept.Add(ordered[i]);
                for (int j = i + 1; j < ordered.Count; j++)
                {
                    if (suppressed[j]) continue;
                    if (Iou(ordered[i], ordered[j]) > nmsThreshold)
                        suppressed[j] = true;
                }
            }
            return kept;
        }

        /// <summary>NMS sonrası en büyük ALANLI yüzü döndürür (referansla aynı seçim).</summary>
        public static FaceDetection? SelectBestFace(List<FaceDetection> dets, float nmsThreshold)
        {
            if (dets.Count == 0) return null;
            var kept = Nms(dets, nmsThreshold);
            if (kept.Count == 0) return null;

            FaceDetection best = kept[0];
            for (int i = 1; i < kept.Count; i++)
                if (kept[i].Area > best.Area) best = kept[i];
            return best;
        }

        private static float Clamp01(float v) => v < 0f ? 0f : (v > 1f ? 1f : v);

        private static float Iou(FaceDetection a, FaceDetection b)
        {
            float ax2 = a.X + a.W, ay2 = a.Y + a.H;
            float bx2 = b.X + b.W, by2 = b.Y + b.H;
            float ix1 = MathF.Max(a.X, b.X), iy1 = MathF.Max(a.Y, b.Y);
            float ix2 = MathF.Min(ax2, bx2), iy2 = MathF.Min(ay2, by2);
            float iw = MathF.Max(0f, ix2 - ix1), ih = MathF.Max(0f, iy2 - iy1);
            float inter = iw * ih;
            float union = a.W * a.H + b.W * b.H - inter;
            return union <= 0f ? 0f : inter / union;
        }
    }
}
