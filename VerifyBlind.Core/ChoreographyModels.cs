using System.Text.Json.Serialization;

namespace VerifyBlind.Core.Models;

// ─────────────────────────────────────────────────────────────────────────────
// DURUŞ + OLAY ÇİFTLEMESİ (koreografi)
//
// Parallaks düz yüzeyi eliyor ama tek başına iki açığı kapatmıyor:
//
//   1. KAYNAK AYRIMI — parallaksı saldırganın kendi yüzü, benzerliği kart sahibinin
//      fotoğrafı sağlıyordu. Parallaks karelerinde KİMİN yüzü olduğuna hiç bakılmıyordu.
//   2. SARMA — yaklaş/uzaklaş hareketi kayıttan sarılarak üretilebiliyor; bir olay (göz
//      kırpma) ise kayıttan talep üzerine üretilemiyor.
//
// Koreografi ikisini aynı kare dizisine bağlar: sunucu hangi MESAFEDE hangi OLAYIN
// isteneceğini seçer; enclave aynı karelerden parallaksı, kimliği ve olayı ölçer.
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Durağın mesafesi — yüz kutusunun kadraj genişliğinde kapladığı hedef orana göre.
///
/// <para>Hedefler istemcinin parallaks adımındakilerle AYNI (0,31 ve 0,62; ortası
/// geometrik orta 0,44). İstemci bu oranları DAYATIR ama enclave onlara GÜVENMEZ: kendi
/// göz-arası ölçümünden duraklar arası ölçeği hesaplar.</para>
/// </summary>
public enum StancePosition
{
    Far = 1,
    Mid = 2,
    Near = 3,
}

/// <summary>
/// Bir durakta istenen olay.
///
/// <para><b>Dağarcık kullanıcı kararıyla seçildi (2026-09-24).</b> Kafa çevirme ve yana
/// yatırma DIŞARIDA: yüz kadrajdan çıkar ya da ölçek yörüngesi kopar — kopan her yer
/// saldırganın kaynak değiştirebileceği yerdir. Tek göz kırpma herkesin yapabildiği bir
/// hareket değil; kaş kaldırma ve dudak büzme de elendi. Kod açık kaynak olduğu için
/// "yapamayanlara atlanabilir" bir hareket, saldırganın da atlayacağı harekettir.</para>
/// </summary>
public enum StanceEvent
{
    None = 0,
    Blink = 1,
    Smile = 2,
    MouthOpen = 3,
    DoubleBlink = 4,
}

/// <summary>Koreografinin bir durağı: hangi mesafede, hangi olay.</summary>
public class ChoreographyStop
{
    [JsonPropertyName("pos")]
    public StancePosition Position { get; set; }

    [JsonPropertyName("event")]
    public StanceEvent Event { get; set; }
}

/// <summary>
/// Sunucunun istediği dizi — el sıkışmada istemciye gider.
///
/// <para>🔴 <b>Dizi nonce'tan TÜRETİLİR</b>, rastgele üretilip unutulmaz. Register'da enclave
/// aynı nonce'tan aynı diziyi yeniden türetir ve kanıtı ona göre ölçer. Eski jest dizisi
/// <c>new Random()</c> ile üretiliyordu ve enclave register anında neyin istendiğini
/// bilmiyordu — istemci kendi dizisini de uydurabilirdi (Android eksik jestleri kendi
/// rastgelesiyle tamamlıyordu).</para>
/// </summary>
public class Choreography
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("stops")]
    public List<ChoreographyStop> Stops { get; set; } = new();
}

/// <summary>
/// İSTEMCİNİN KANITI — her durak için tam kareler.
///
/// <para>Kareler TAM KARE (uzun kenar 480, JPEG) — yüz kırpması DEĞİL: parallaks yüz ile
/// arka plan arasındaki farkı ölçer, arka plan kesilirse ölçülecek bir şey kalmaz.</para>
///
/// <para>⚠️ Buradaki sayıların HİÇBİRİNE güvenilmez. Enclave konumu, olayı ve kimliği
/// kendi ölçümüyle çıkarır; istemcinin sayıları yalnız kıyas ve teşhis içindir.</para>
/// </summary>
public class ChoreographyProof
{
    [JsonPropertyName("version")]
    public int Version { get; set; }

    /// <summary>Durak sırası koreografiyle AYNI olmak zorunda.</summary>
    [JsonPropertyName("stops")]
    public List<ChoreographyProofStop> Stops { get; set; } = new();

    /// <summary>
    /// Arka plan doku enerjisi — İLK UZAK durakta, eski parallaks adımıyla AYNI ölçüyle (tüm
    /// kare, yüz kutusu × 1,6 dışarıda). Eşik (14) bu ölçüyle kalibre edildi; sunucu bu sayıyla
    /// "arkanızda desen yok" / "arka plan çok yakın" mesajları arasında seçim yapıyor.
    /// </summary>
    [JsonPropertyName("bg_texture")]
    public double? BgTexture { get; set; }

    /// <summary>
    /// Aynı ölçü YAKIN ÇIPADA (yüz kutusu × 1,15 dışarıda) — istemcinin erken uyarısı buna bakar.
    ///
    /// <para>Yaklaştıkça arka plan kadrajdan çıkar; yakın karede görünen, uzak karede
    /// görünenin alt kümesidir. ORB'un eşleştireceği desen iki karede de bulunmalı, yani
    /// bağlayıcı olan yakın uç. Yatak koşularında uzak karedeki doku 15-17 ile kapıyı geçti,
    /// yakın uçta eşleşme dördünde de çöktü. ⚠️ Eşiği KALİBRE EDİLMEDİ; bu alan onun için.</para>
    /// </summary>
    [JsonPropertyName("bg_texture_near")]
    public double? BgTextureNear { get; set; }

    [JsonPropertyName("elapsed_ms")]
    public int? ElapsedMs { get; set; }

    /// <summary>Dizinin baştan başlatılma sayısı (yüz kaybı, duruşta ölçek kayması).</summary>
    [JsonPropertyName("resets")]
    public int? Resets { get; set; }

    /// <summary>Yanlış olay sayısı (istenmeyen kasıtlı hareket).</summary>
    [JsonPropertyName("wrong_events")]
    public int? WrongEvents { get; set; }
}

/// <summary>Bir durağın kareleri.</summary>
public class ChoreographyProofStop
{
    /// <summary>
    /// Duruş kareleri (nötr yüz) — en fazla iki: duruşun başı ve sonu.
    ///
    /// <para>İlki parallaks ve kimlik ölçümüne girer. İkisinin farkı "donmuş kare" ölçüsüdür:
    /// elde tutulan telefon her zaman titrer, duraklatılmış bir videoda iki kare aynıdır.</para>
    /// </summary>
    [JsonPropertyName("hold")]
    public List<string> Hold { get; set; } = new();

    /// <summary>Olay anının kareleri — olaysız durakta boş, çift kırpmada iki.</summary>
    [JsonPropertyName("event")]
    public List<string> Event { get; set; } = new();

    /// <summary>İstemcinin ölçtüğü yüz/kadraj oranı — DOĞRULANMAZ.</summary>
    [JsonPropertyName("face_fraction")]
    public double? FaceFraction { get; set; }

    /// <summary>Bu durakta olay kaç denemede tuttu — teşhis.</summary>
    [JsonPropertyName("attempts")]
    public int? Attempts { get; set; }
}

/// <summary>
/// ENCLAVE'İN ÖLÇÜMÜ — relay ölçüm tablosuna JSON olarak yazar.
///
/// <para>Kapılar ayrı: yapı bozuksa ve kimlik tutmuyorsa kayıt reddedilir, parallaks kapısı
/// <see cref="PlanarityOutcome"/> üzerinden çalışır. Buradaki diğer her sayı ÖLÇÜMDÜR; eşiği
/// meşru dağılım görülmeden konmayacak.</para>
/// </summary>
public class ChoreographyOutcome
{
    /// <summary>measured | invalid</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    /// <summary>Yapı bozuksa NEDEN — sabit küme (stops, hold, event, frame).</summary>
    [JsonPropertyName("invalid_reason")]
    public string? InvalidReason { get; set; }

    /// <summary>İstenen dizi, kısa biçim: "N,F+blink,M,N+smile".</summary>
    [JsonPropertyName("demanded")]
    public string? Demanded { get; set; }

    /// <summary>
    /// Duraklar arası ölçek uyumu: istenen ölçek değişimi ile ölçülenin log farkının EN
    /// BÜYÜĞÜ. 0 = kusursuz; ln(1,2) ≈ 0,18 "yüzde 20 sapma".
    /// </summary>
    [JsonPropertyName("position_err_max")]
    public double? PositionErrMax { get; set; }

    /// <summary>Durak başına enclave ölçeği (en uzak durağa göre).</summary>
    [JsonPropertyName("stop_scales")]
    public List<double>? StopScales { get; set; }

    /// <summary>
    /// Duruş içi hareketin EN KÜÇÜĞÜ — iki duruş karesi arasındaki ortalama piksel farkı
    /// (0-255). Donmuş/duraklatılmış videoda ~0; elde tutulan telefonda belirgin.
    /// </summary>
    [JsonPropertyName("hold_motion_min")]
    public double? HoldMotionMin { get; set; }

    /// <summary>Duruş içi ölçek kaymasının EN BÜYÜĞÜ, |ln(s2/s1)|.</summary>
    [JsonPropertyName("hold_scale_dev_max")]
    public double? HoldScaleDevMax { get; set; }

    /// <summary>
    /// 🔴 KİMLİK — parallaksın ölçüldüğü her duruş karesinin çip fotoğrafına benzerliği.
    /// Kapı bunların EN KÜÇÜĞÜNE bakar.
    /// </summary>
    [JsonPropertyName("identity")]
    public List<double>? Identity { get; set; }

    [JsonPropertyName("identity_min")]
    public double? IdentityMin { get; set; }

    /// <summary>Olay karelerinin çip benzerliği — YALNIZ ÖLÇÜM (gülümserken ne kadar düşüyor).</summary>
    [JsonPropertyName("event_identity")]
    public List<double>? EventIdentity { get; set; }

    [JsonPropertyName("events")]
    public List<EventMeasurement>? Events { get; set; }

    /// <summary>
    /// KONTUR ORANI (kulak fikri) — yüz kutusu genişliği / göz-arası mesafe, yakın durakta
    /// uzak durağa bölünmüş.
    ///
    /// <para>Kafanın yanları gözlerden geride. Kamera yaklaştıkça perspektif gözleri yanlara
    /// göre büyütür, yanlar görünmez olur (kulakların kaybolması bunun en belirgin hâli).
    /// Düz yüzeyde oran SABİT → 1,00. Arka plandan bağımsız: duvar dibinde de çalışır.</para>
    ///
    /// <para>⚠️ YuNet kutusu kulakları değil yanak/çene hattını izler; aynı fizik, daha zayıf
    /// sinyal. Ölçülebilir mi, önce dağılım.</para>
    /// </summary>
    [JsonPropertyName("contour_far")]
    public double? ContourFar { get; set; }

    [JsonPropertyName("contour_near")]
    public double? ContourNear { get; set; }

    [JsonPropertyName("contour_ratio")]
    public double? ContourRatio { get; set; }

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

    /// <summary>Yakın çıpadaki doku — istemci uyarısının eşiğini kalibre etmek için.</summary>
    [JsonPropertyName("bg_texture_near")]
    public double? BgTextureNear { get; set; }

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
    [JsonPropertyName("stop")]
    public int Stop { get; set; }

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
