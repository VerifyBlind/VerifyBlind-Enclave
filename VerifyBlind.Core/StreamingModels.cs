using System.Text.Json.Serialization;

namespace VerifyBlind.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// CANLI BENZERLİK AKIŞI (streaming similarity) — ölçüm toplama
//
// Amaç: bugün cihazdaki 0.65 kapısında düşen her deneme enclave'e HİÇ ulaşmıyor, dolayısıyla
// kaç meşru kullanıcıyı hatalı reddettiğimiz ÖLÇÜLEMİYOR. Canlılık sürerken enclave'e kare
// göndermek iki şeyi birden çözer: (a) cihaz skoru eşiğin altında kalsa bile enclave "geçti"
// derse submit açılır, (b) her deneme ölçülebilir bir veri noktasına dönüşür.
//
// ⚠️ Bu bir güvenlik gevşemesi DEĞİLDİR. Cihazdaki 0.65 hiçbir zaman güvenlik kontrolü değildi
// (yerel bir boolean; kötü niyetli istemci zaten yamalayabilir). Gerçek karar hep enclave'de ve
// register akışından HİÇBİR kontrol kaldırılmadı.
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Akış başında (NFC bittikten sonra) bir kez çağrılır: enclave DG2'den yüz gömme vektörünü
/// hesaplayıp <see cref="FlowId"/> ile RAM'de önbelleğe alır. Sonraki karelerde yalnız selfie
/// gider — DG2 bir daha gönderilmez.
///
/// ⚠️ Önbellek YALNIZ streaming içindir. Final register bu önbelleğe ASLA bakmaz: DG2'yi bugünkü
/// gibi şifreli yükten okur ve her şeyi baştan hesaplar. Streaming yolu tamamen kapatılsa bile
/// register aynen çalışır (durumsuz).
/// </summary>
public class StreamingPrepareRequest
{
    /// <summary>Akış izleme numarası (GUID). Kimlikle bağ TAŞIMAZ.</summary>
    [JsonPropertyName("flow_id")]
    public string FlowId { get; set; } = string.Empty;

    /// <summary>RSA-OAEP ile sarılmış AES anahtarı — DG2 açıkta gitmez.</summary>
    [JsonPropertyName("encrypted_key")]
    public string EncryptedKey { get; set; } = string.Empty;

    /// <summary>AES-GCM ile şifreli <see cref="StreamingPreparePayload"/>.</summary>
    [JsonPropertyName("aes_blob")]
    public string AesBlob { get; set; } = string.Empty;
}

/// <summary>Şifreli prepare yükü — çipten okunan ham DG2.</summary>
public class StreamingPreparePayload
{
    /// <summary>Ham DG2 EF baytları (Base64). Enclave gömmeyi bundan çıkarır.</summary>
    public string DG2 { get; set; } = string.Empty;
}

/// <summary>
/// Canlılık sürerken gönderilen tek kare: selfie + kendi 2,7× anti-spoof kırpması.
///
/// ⚠️ İkisi AYNI kareden gelmelidir (K6). Benzerliği bir kareden, canlılığı başkasından almak
/// gerçek bir açıktır: saldırgan gerçek yüzü benzerliğe, canlı kırpmayı anti-spoof'a verirdi.
/// </summary>
public class StreamingCheckRequest
{
    [JsonPropertyName("flow_id")]
    public string FlowId { get; set; } = string.Empty;

    [JsonPropertyName("encrypted_key")]
    public string EncryptedKey { get; set; } = string.Empty;

    /// <summary>AES-GCM ile şifreli <see cref="StreamingCheckPayload"/>.</summary>
    [JsonPropertyName("aes_blob")]
    public string AesBlob { get; set; } = string.Empty;

    /// <summary>Akış içinde kaçıncı gönderim (ölçüm satırında saklanır).</summary>
    [JsonPropertyName("seq")]
    public int Seq { get; set; }

    /// <summary>Cihazın kendi ölçüleri — DOĞRULANMAZ, aralık kontrolünden geçirilip saklanır.</summary>
    [JsonPropertyName("device_metrics")]
    public DeviceFrameMetrics? DeviceMetrics { get; set; }
}

/// <summary>Şifreli kare yükü — selfie ve kırpma açıkta gitmez.</summary>
public class StreamingCheckPayload
{
    /// <summary>Hizalanmış 112×112 selfie (Base64 PNG).</summary>
    public string UserSelfie { get; set; } = string.Empty;

    /// <summary>Aynı karenin 2,7× geniş anti-spoof kırpması (Base64 JPEG 80×80).</summary>
    public string AntiSpoofCrop { get; set; } = string.Empty;
}

/// <summary>
/// Streaming kare sonucu. Cihaz yalnız <see cref="SimilarityPassed"/>'e bakar; skorlar ölçüm
/// içindir.
/// </summary>
public class StreamingCheckResponse
{
    /// <summary>Enclave benzerlik eşiğini geçti mi.</summary>
    [JsonPropertyName("similarity_passed")]
    public bool SimilarityPassed { get; set; }

    /// <summary>ArcFace kosinüs benzerliği (0-1).</summary>
    [JsonPropertyName("match_score")]
    public double MatchScore { get; set; }

    /// <summary>MiniFASNetV2 P(live).</summary>
    [JsonPropertyName("p_live")]
    public double PLive { get; set; }

    /// <summary>3-sınıf softmax kırılımı [fake1, real, fake2] — %46,2 anomalisi için.</summary>
    [JsonPropertyName("c0")]
    public double C0 { get; set; }

    [JsonPropertyName("c1")]
    public double C1 { get; set; }

    [JsonPropertyName("c2")]
    public double C2 { get; set; }

    /// <summary>pass | fail_similarity | fail_liveness</summary>
    [JsonPropertyName("outcome")]
    public string Outcome { get; set; } = string.Empty;
}

/// <summary>
/// Cihazın kendi ölçtüğü kare sinyalleri. Zaten hesaplanıyorlar ama hiçbir yere gönderilmiyorlardı.
///
/// ⚠️ Uç kimlik doğrulaması istemez → GÖVDEDEN GELEN SAYIYA GÜVENİLMEZ. Sunucu tarafında aralık
/// kontrolünden geçirilir (RegisterFlowEvent.NormalizeScore kalıbı), geçersizse sessizce düşer.
/// Telemetri asla akışı bozmaz.
/// </summary>
public class DeviceFrameMetrics
{
    /// <summary>MobileFaceNet benzerliği (0-100). Enclave skoruyla KIYASLANAMAZ — farklı model.</summary>
    [JsonPropertyName("device_match_score")]
    public int? DeviceMatchScore { get; set; }

    [JsonPropertyName("luma")]
    public int? Luma { get; set; }

    [JsonPropertyName("sharpness")]
    public int? Sharpness { get; set; }

    [JsonPropertyName("quality")]
    public int? Quality { get; set; }

    [JsonPropertyName("yaw")]
    public int? Yaw { get; set; }

    [JsonPropertyName("pitch")]
    public int? Pitch { get; set; }

    [JsonPropertyName("roll")]
    public int? Roll { get; set; }

    /// <summary>Yüz genişliğinin kare genişliğine oranı (yüzde, 0-100).</summary>
    [JsonPropertyName("face_width_ratio")]
    public int? FaceWidthRatio { get; set; }

    [JsonPropertyName("gesture_count")]
    public int? GestureCount { get; set; }

    [JsonPropertyName("wrong_gesture_count")]
    public int? WrongGestureCount { get; set; }

    [JsonPropertyName("elapsed_ms")]
    public int? ElapsedMs { get; set; }

    /// <summary>
    /// Bu gönderimden önce, oran freni yüzünden GÖNDERİLMEDEN elenen iyileşme sayısı.
    ///
    /// Elenen karenin KENDİSİNİ göndermek veriyi kareyle büyütürdü; bu sayaç, topladığımız
    /// dağılımın ne kadar yanlı olduğunu ölçmenin ucuz yolu.
    /// </summary>
    [JsonPropertyName("skipped_count")]
    public int? SkippedCount { get; set; }

    /// <summary>
    /// Yalnız final aday: bu karenin streaming'de gönderildiği <c>seq</c>. Hiç gönderilmediyse null.
    /// İki aday farklı karelerken "hangi kare hangi karara yol açtı" ancak bununla yanıtlanır.
    /// </summary>
    [JsonPropertyName("source_seq")]
    public int? SourceSeq { get; set; }

    [JsonPropertyName("platform")]
    public string? Platform { get; set; }

    [JsonPropertyName("app_version")]
    public string? AppVersion { get; set; }

    [JsonPropertyName("device_model")]
    public string? DeviceModel { get; set; }
}

/// <summary>
/// Final register yükündeki TEK bir aday: kendi selfie'si + KENDİ 2,7× kırpması.
///
/// ⚠️ Benzerlik bir adaydan, canlılık başka adaydan ALINAMAZ (K6). Her aday bir bütün olarak
/// değerlendirilir; enclave adayları sırayla normal kapıdan geçirir ve ilk GEÇEN kazanır.
/// </summary>
public class RegistrationCandidate
{
    /// <summary>1 = istemcinin en iyi seçtiği kare, 2 = enclave'in streaming'de onayladığı kare.</summary>
    public int Rank { get; set; }

    /// <summary>Hizalanmış 112×112 selfie (Base64 PNG).</summary>
    public string UserSelfie { get; set; } = string.Empty;

    /// <summary>Aynı karenin 2,7× geniş anti-spoof kırpması (Base64 JPEG 80×80).</summary>
    public string AntiSpoofCrop { get; set; } = string.Empty;

    /// <summary>
    /// AYNI karenin 4,0× kırpması — satıcının ikinci ölçeği. Model henüz kurulu değil;
    /// gerekçe <see cref="SecurePayload.AntiSpoofCrop40"/>. Boş gelmesi normaldir.
    /// </summary>
    public string AntiSpoofCrop40 { get; set; } = string.Empty;

    /// <summary>Cihaz ölçüleri — ölçüm satırına yazılır (doğrulanmaz).</summary>
    public DeviceFrameMetrics? DeviceMetrics { get; set; }
}

/// <summary>
/// Olay dizisi ölçümünün ölçüm tablosundaki satırı — relay bunu akış başına TEK satır olarak
/// yazar (<c>phase = "zoom"</c>).
///
/// <para>⚠️ <b>Adı tarihsel.</b> Bu satır önce yakınlaştırma (düzlem-dışılık), sonra parallaks
/// ölçümünü taşıyordu; ikisi de 2026-09-25'te kaldırıldı (mesafe tabanlı yöntemler patent
/// riski — bkz. <see cref="ChoreographyProof"/> dosyasının başı). Tel alanı (<c>planarity</c>),
/// DB sütunları ve bu sınıf ölçüm geçmişi bozulmasın diye aynı adla kalıyor; bugün taşıdığı
/// tek ölçüm <see cref="Choreography"/>.</para>
/// </summary>
public class PlanarityOutcome
{
    /// <summary>Sabit küme: <see cref="PlanarityStatuses"/>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>
    /// Dizinin kullanıcıya SÜRE maliyeti (ms) — istemciden gelir, olduğu gibi taşınır.
    ///
    /// <para><b>Neden kaydedilmeli:</b> bu adım her meşru kayda eklenen bir yüktür ve
    /// "ne kadar sürüyor" sorusunun cevabı, dizinin uzunluğu kararının yarısıdır.</para>
    ///
    /// <para>⚠️ Cihazdan gelir, DOĞRULANMAZ; relay aralık kontrolünden geçirir.</para>
    /// </summary>
    [JsonPropertyName("elapsed_ms")]
    public int? ElapsedMs { get; set; }

    /// <summary>Olay dizisinin ölçümü — kanıt geldiyse dolu, eski istemcide boş.</summary>
    [JsonPropertyName("choreography")]
    public ChoreographyOutcome? Choreography { get; set; }
}

/// <summary>
/// Enclave'in final register'da her aday için ürettiği sonuç — relay bunu ölçüm tablosuna yazar.
///
/// ⚠️ İKİ ADAY DA yazılır: 1. aday düşüp 2. aday geçtiyse ikisi de görünür. Bu, cihazın "en iyi"
/// hükmü ile enclave'in hükmü arasındaki SAPMANIN etiketli örneğidir — 0.65'in doğru sayı olup
/// olmadığını çözecek veri budur. Sadece geçeni loglamak bu bilgiyi yok eder.
/// </summary>
public class CandidateOutcome
{
    [JsonPropertyName("rank")]
    public int Rank { get; set; }

    [JsonPropertyName("match_score")]
    public double MatchScore { get; set; }

    [JsonPropertyName("p_live")]
    public double PLive { get; set; }

    [JsonPropertyName("c0")]
    public double C0 { get; set; }

    [JsonPropertyName("c1")]
    public double C1 { get; set; }

    [JsonPropertyName("c2")]
    public double C2 { get; set; }

    /// <summary>
    /// İKİNCİ ÖLÇEĞİN (4,0× kırpma, MiniFASNetV1SE) canlılık olasılığı — <b>YALNIZ ÖLÇÜM.</b>
    ///
    /// <para>Karara GİRMEZ. Fotoğraf ölçümünde bu model ekranlara daha yüksek "canlı" puanı
    /// verdi ve topluluk 2,7'nin tek başınadan kötü ayırdı; yine de gerçek boru hattında
    /// (ön kamera, 1080p) farklı davranabilir, o yüzden kaydediliyor. Ölçülemediyse null.</para>
    /// </summary>
    [JsonPropertyName("p_live_40")]
    public double? PLive40 { get; set; }

    /// <summary>pass | fail_similarity | fail_liveness</summary>
    [JsonPropertyName("outcome")]
    public string Outcome { get; set; } = string.Empty;
}

/// <summary>
/// Akış bitiş bildirimi — canlılık ekranı kapanırken gönderilir.
///
/// 🔴 Bu işin varlık sebebi olan vakayı görünür kılar: "enclave geçirirdi ama kullanıcı pes
/// etti". Streaming satırları yazılıyordu ama akışın NASIL bittiği hiçbir yerde yoktu.
///
/// Best-effort: düşerse yalnız o akışın bitiş etiketi kaybolur, satırlar yerinde kalır.
/// </summary>
public class StreamingReleaseRequest
{
    [JsonPropertyName("flow_id")]
    public string FlowId { get; set; } = string.Empty;

    /// <summary>
    /// Canlılık ekranının nasıl bittiği (sabit küme; relay bilinmeyeni düşürür):
    /// submitted | abandoned | timeout_gesture | timeout_session | too_many_errors |
    /// match_failed | no_selfie.
    /// </summary>
    [JsonPropertyName("flow_outcome")]
    public string? FlowOutcome { get; set; }
}

/// <summary>Ölçüm satırı sonuç kümesi — sabit, serbest metin değil.</summary>
public static class FrameOutcomes
{
    public const string Pass           = "pass";
    public const string FailSimilarity = "fail_similarity";
    public const string FailLiveness   = "fail_liveness";

    public static bool IsValid(string? v) =>
        v is Pass or FailSimilarity or FailLiveness;
}

/// <summary>
/// Ölçüm satırının durumu — sabit küme.
///
/// <para>⚠️ <b>PAYLAŞILAN tanım.</b> Enclave üretir, relay saklar. İki tarafta ayrı sabitler
/// tutmak <c>EnclaveErrorCodes</c>'ta sapmaya yol açmıştı: enclave'in ürettiği bir etiket relay'de
/// "bilinmeyen" sayılırsa satır sessizce boş yazılır ve ölçüm görünmez olur.</para>
///
/// <para>Eski satırlarda parallaks dönemine ait başka değerler de var (flat_surface, no_texture
/// …); onlar geçmişte kalıyor, yenileri yalnız bu kümeden.</para>
/// </summary>
public static class PlanarityStatuses
{
    /// <summary>Olay dizisi ölçüldü.</summary>
    public const string Measured = "measured";

    /// <summary>İstemci dizi kanıtı göndermedi — mağazadaki eski jest akışı.</summary>
    public const string NoProof = "no_proof";

    /// <summary>
    /// Kanıt geldi ama yapısı istenen diziyle uyuşmuyor (eksik adım, çözülemeyen kare). Kayıt
    /// <c>ERR_CHOREO_INVALID</c> ile reddedilir; ayrıntı <see cref="ChoreographyOutcome.InvalidReason"/>.
    /// </summary>
    public const string Unmeasured = "unmeasured";

    public static bool IsValid(string? v) => v is Measured or NoProof or Unmeasured;
}
