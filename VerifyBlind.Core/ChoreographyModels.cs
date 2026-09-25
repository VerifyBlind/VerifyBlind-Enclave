using System.Text.Json.Serialization;

namespace VerifyBlind.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// OLAY DİZİSİ (koreografi)
//
// Sunucu nonce'tan rastgele sırada yüz hareketleri seçer (göz kırpma, gülümseme, ağız açma,
// çift kırpma). İstemci her hareketten ÖNCE bir nötr kare, hareket ANINDA olay karesi toplar.
// Enclave aynı nonce'tan diziyi yeniden türetir ve gönderilen kareleri ona göre ölçer:
// yapı, HER karede kart sahibinin yüzü, olay özellikleri.
//
// Kapattığı açık KAYNAK AYRIMI: benzerliği kart sahibinin fotoğrafı, hareketi başka bir yüz
// sağlayamaz — hareketin yapıldığı karede de kimlik aranır. Fotoğraf ise hareket yapamaz.
//
// 🔴 2026-09-25: MESAFE KALDIRILDI. Önceki sürüm uzak/orta/yakın duraklarda duruş istiyor ve
// yüz↔arka plan parallaksından 3B çıkarıyordu. İki mesafede görüntü karşılaştırarak 3B çıkaran
// yöntemler FaceTec patent istemlerine düşüyor; kullanıcı kararıyla dizi tek mesafede. Son hâli
// git'te (enclave 1c6dfa1). Mesafe/ölçek değişimine dayanan bir yöntem geri getirilmeden önce
// o karar yeniden değerlendirilmeli.
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Dizide istenebilen hareket.
///
/// <para><b>Dağarcık kullanıcı kararıyla seçildi.</b> Kafa çevirme DIŞARIDA: yüz profile döner,
/// kimlik o karede ölçülemez — kimliğin ölçülemediği her kare saldırganın kaynak
/// değiştirebileceği yerdir. Tek göz kırpma herkesin yapabildiği bir hareket değil; kaş kaldırma
/// ve dudak büzme de elendi. Kod açık kaynak olduğu için "yapamayanlara atlanabilir" bir hareket,
/// saldırganın da atlayacağı harekettir.</para>
///
/// <para>Eski jest akışının <see cref="LivenessAction"/>'ı mağazadaki eski sürümler için
/// yaşıyor; bu tür yeni akışındır.</para>
/// </summary>
public enum LivenessEvent
{
    None = 0,
    Blink = 1,
    Smile = 2,
    MouthOpen = 3,
    DoubleBlink = 4,
}

/// <summary>
/// Sunucunun istediği dizi — el sıkışmada istemciye gider.
///
/// <para>🔴 <b>Dizi nonce'tan TÜRETİLİR</b>, rastgele üretilip unutulmaz. Register'da enclave
/// aynı nonce'tan aynı diziyi yeniden türetir ve kanıtı ona göre ölçer. Eski jest dizisi
/// <c>new Random()</c> ile üretiliyordu ve enclave register anında neyin istendiğini
/// bilmiyordu — istemci kendi dizisini de uydurabilirdi.</para>
/// </summary>
public class Choreography
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 2;

    /// <summary>İstenen hareketler, istenme sırasıyla (sayı olarak serileşir).</summary>
    [JsonPropertyName("events")]
    public List<LivenessEvent> Events { get; set; } = new();
}

/// <summary>
/// İSTEMCİNİN KANITI — her hareket için bir adım.
///
/// <para>Kareler yüzün çevresinden kırpılmış JPEG (uzun kenar en fazla 480). Arka plan artık
/// ölçülmüyor; kırpma hem enclave'e daha çok yüz pikseli verir hem de kullanıcının odasını
/// gereksiz yere taşımaz.</para>
///
/// <para>⚠️ Buradaki sayıların HİÇBİRİNE güvenilmez. Enclave olayı ve kimliği kendi ölçümüyle
/// çıkarır; istemcinin sayıları yalnız kıyas ve teşhis içindir.</para>
/// </summary>
public class ChoreographyProof
{
    [JsonPropertyName("version")]
    public int Version { get; set; }

    /// <summary>Adım sırası diziyle AYNI olmak zorunda.</summary>
    [JsonPropertyName("steps")]
    public List<ChoreographyProofStep> Steps { get; set; } = new();

    [JsonPropertyName("elapsed_ms")]
    public int? ElapsedMs { get; set; }

    /// <summary>Dizinin baştan başlatılma sayısı (yüz kaybı, takip numarası değişimi).</summary>
    [JsonPropertyName("resets")]
    public int? Resets { get; set; }

    /// <summary>Yanlış olay sayısı (istenmeyen kasıtlı hareket).</summary>
    [JsonPropertyName("wrong_events")]
    public int? WrongEvents { get; set; }

    /// <summary>
    /// Yüz KAYBOLMADAN değişen ML Kit takip numarası sayısı — yalnız ölçüm. İstemci numara
    /// değişimini ancak yüz gerçekten kaybolduysa sıfırlama sebebi sayıyor; kesintisiz algılamada
    /// ML Kit'in numarayı ne sıklıkla yenilediği bilinmiyor ve bu sayı onun için.
    /// </summary>
    [JsonPropertyName("tracking_changes")]
    public int? TrackingChanges { get; set; }

    /// <summary>
    /// İstemcinin karar zaman çizelgesi (ASCII): adım başlangıçları, olay sırasında
    /// göz/gülümseme/ağız değerleri, yanlış hareketler, sıfırlama sebepleri. DOĞRULANMAZ —
    /// teşhis ve eşik kalibrasyonu için.
    /// </summary>
    [JsonPropertyName("trace")]
    public string? Trace { get; set; }
}

/// <summary>Bir hareketin kareleri.</summary>
public class ChoreographyProofStep
{
    /// <summary>
    /// Hareketten hemen ÖNCEKİ nötr kare — tam olarak bir tane.
    ///
    /// <para>İki işi var: kimlik (hareketler ARASINDAKİ yüz de kart sahibi olmalı) ve olay
    /// ölçümünün referansı (olay karesi aynı kişinin aynı ışıktaki nötr hâline göre okunur).</para>
    /// </summary>
    [JsonPropertyName("neutral")]
    public List<string> Neutral { get; set; } = new();

    /// <summary>Olay anının kareleri — çift kırpmada iki, diğerlerinde bir.</summary>
    [JsonPropertyName("event")]
    public List<string> Event { get; set; } = new();

    /// <summary>Bu adımda olay kaç denemede tuttu — teşhis.</summary>
    [JsonPropertyName("attempts")]
    public int? Attempts { get; set; }
}

/// <summary>
/// ENCLAVE'İN ÖLÇÜMÜ — relay ölçüm tablosuna JSON olarak yazar.
///
/// <para>Kapılar: yapı bozuksa ve kimlik herhangi bir karede tutmuyorsa kayıt reddedilir.
/// Olay özellikleri ÖLÇÜMDÜR: sahadaki ilk 11 koşuda (2026-09-24/25) göz kapanma ve ağız
/// koyuluğu ölçüleri meşru hareketlerde de sıfır ya da negatif çıkabildi — eşik konursa meşru
/// kullanıcı reddedilir.</para>
/// </summary>
public class ChoreographyOutcome
{
    /// <summary>measured | invalid</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>Yapı bozuksa NEDEN — sabit küme (version, steps, neutral, event, frame).</summary>
    [JsonPropertyName("invalid_reason")]
    public string? InvalidReason { get; set; }

    /// <summary>İstenen dizi, kısa biçim: "blink,mouth_open,smile".</summary>
    [JsonPropertyName("demanded")]
    public string? Demanded { get; set; }

    /// <summary>Her adımın nötr karesinin çip fotoğrafına benzerliği.</summary>
    [JsonPropertyName("identity")]
    public List<double>? Identity { get; set; }

    /// <summary>
    /// Olay karelerinin çip fotoğrafına benzerliği. Sahada gülümseme ve ağız açma benzerliği
    /// nötr kareye göre en fazla ~0,1 düşürdü (0,52-0,72); eşik 0,20 — kapıya girer.
    /// </summary>
    [JsonPropertyName("event_identity")]
    public List<double>? EventIdentity { get; set; }

    /// <summary>
    /// 🔴 KAPI — nötr VE olay karelerinin EN KÜÇÜK benzerliği. Hareketi başka bir yüzün yaptığı
    /// tek bir kare bile kaydı düşürür.
    /// </summary>
    [JsonPropertyName("identity_min")]
    public double? IdentityMin { get; set; }

    [JsonPropertyName("events")]
    public List<EventMeasurement>? Events { get; set; }

    [JsonPropertyName("frames")]
    public int Frames { get; set; }

    [JsonPropertyName("faces")]
    public int Faces { get; set; }

    [JsonPropertyName("resets")]
    public int? Resets { get; set; }

    [JsonPropertyName("wrong_events")]
    public int? WrongEvents { get; set; }

    [JsonPropertyName("elapsed_ms")]
    public int? ElapsedMs { get; set; }

    [JsonPropertyName("tracking_changes")]
    public int? TrackingChanges { get; set; }

    /// <summary>İstemcinin iz kaydı — enclave 4000 karakterde kırpar, ASCII dışını ayıklar.</summary>
    [JsonPropertyName("trace")]
    public string? Trace { get; set; }

    /// <summary>Ölçümün enclave'e maliyeti (ms).</summary>
    [JsonPropertyName("cost_ms")]
    public int CostMs { get; set; }
}

/// <summary>
/// Bir olayın enclave ölçümü — üç özellik de HER olay karesinde ölçülür.
///
/// <para>Neden hepsi: ayırt ediciliği ancak böyle görürüz. Kırpma istendiğinde göz ölçüsü
/// yükselip gülümseme ölçüsü düz kalıyorsa sinyal var; hepsi birlikte oynuyorsa yok.</para>
/// </summary>
public class EventMeasurement
{
    [JsonPropertyName("step")]
    public int Step { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    /// <summary>1 − (olay karesinde göz kontrastı / nötr karede). Kapalı göz → pozitif.</summary>
    [JsonPropertyName("eye_closure")]
    public double? EyeClosure { get; set; }

    /// <summary>(olay karesinde ağız genişliği / göz-arası) ÷ nötr karedeki − 1. Gülümseme → pozitif.</summary>
    [JsonPropertyName("mouth_widen")]
    public double? MouthWiden { get; set; }

    /// <summary>Ağız içi koyu piksel oranı farkı (olay − nötr). Açık ağız → pozitif.</summary>
    [JsonPropertyName("mouth_dark")]
    public double? MouthDark { get; set; }
}
