namespace VerifyBlind.Enclave.Services.FaceAlignment
{
    /// <summary>
    /// 2D similarity (Umeyama) en-küçük-kareler dönüşümü — yüz landmark'larını ArcFace
    /// kanonik şablonuna hizalamak için. Yansımasız; ölçek+döndürme+öteleme (4 DOF).
    /// </summary>
    public static class Umeyama
    {
        /// <summary>
        /// src (Nx2, x0,y0,x1,y1,...) noktalarını dst (Nx2) üzerine taşıyan 2x3 afin matris
        /// döndürür: [m00,m01,m02, m10,m11,m12] (satır-büyük). Uygulama:
        /// x' = m00*x + m01*y + m02 ; y' = m10*x + m11*y + m12.
        /// </summary>
        public static float[] SimilarityTransform(float[] src, float[] dst)
        {
            if (src.Length != dst.Length || src.Length < 4 || src.Length % 2 != 0)
                throw new System.ArgumentException("src ve dst eşit, çift uzunlukta (≥2 nokta) olmalı.");

            int n = src.Length / 2;

            // Çift hassasiyetli birikim — golden (numpy float64) ile eşleşmek için.
            double mpx = 0, mpy = 0, mqx = 0, mqy = 0;
            for (int i = 0; i < n; i++)
            {
                mpx += src[2 * i]; mpy += src[2 * i + 1];
                mqx += dst[2 * i]; mqy += dst[2 * i + 1];
            }
            mpx /= n; mpy /= n; mqx /= n; mqy /= n;

            // C = Σ(a·b), S = Σ(a×b), var = Σ|a|²  (a=src-merkez, b=dst-merkez)
            double c = 0, s = 0, varSum = 0;
            for (int i = 0; i < n; i++)
            {
                double ax = src[2 * i] - mpx, ay = src[2 * i + 1] - mpy;
                double bx = dst[2 * i] - mqx, by = dst[2 * i + 1] - mqy;
                c += ax * bx + ay * by;
                s += ax * by - ay * bx;
                varSum += ax * ax + ay * ay;
            }

            if (varSum == 0)
                throw new System.ArgumentException("src noktaları çakışık (var=0) — dönüşüm tanımsız.");

            // Yansımasız 2D similarity kapalı-formu (Umeyama'nın 2D özel hâli):
            //   sR = [[sc,-ss],[ss,sc]],  sc = C/var,  ss = S/var
            double sc = c / varSum;
            double ss = s / varSum;
            double tx = mqx - (sc * mpx - ss * mpy);
            double ty = mqy - (ss * mpx + sc * mpy);

            return new[]
            {
                (float)sc, (float)(-ss), (float)tx,
                (float)ss, (float)sc,    (float)ty
            };
        }
    }
}
