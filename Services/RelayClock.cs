namespace VerifyBlind.Enclave.Services;

/// <summary>
/// Relay'in bildirdiği NTP-senkron saat — enclave'in kendi saatine karşı bir DÜZELTME kaynağı.
///
/// Nitro enclave'lerde NTP yoktur; saat açılışta ana makineden tohumlanır ve sonra kayar. Enclave
/// kendi attestation belgesinin ne zaman yenileneceğine de kendi saatiyle karar veriyordu: saat
/// geri kalınca "daha vaktim var" deyip yenilemedi ve gerçekte süresi dolmuş bir AWS sertifikası
/// servis etti. 2026-08-25'te üretimde tam olarak bu oldu — kullanıcılar uygulamayı açamadı ve
/// sunucu tarafı 24 saat boyunca hiçbir şey fark etmedi.
///
/// ⚠️ GÜVENLİK YÖNÜ KASITLI: <see cref="EffectiveUtcNow"/> saati YALNIZCA İLERİ taşır
/// (<c>max</c>). Relay güvenilmeyen bir bileşendir, ama bu tek yönlülük onu zararsız kılar:
/// yalan bir saatle yapılabilecek en kötü şey FAZLADAN yenileme tetiklemektir (ki onun da hız
/// sınırı var), asla süresi dolmuş bir belgenin servis edilmesini sağlamak değil. Geri yönde
/// etkisi olsaydı tam tersi doğru olurdu ve bu sınıf bir saldırı yüzeyi olurdu.
///
/// Son bildirilen değer saklanır, görülen en büyük değer DEĞİL: tek seferlik bozuk/uçuk bir saat
/// kalıcı olarak yerleşmesin, bir sonraki istekte kendiliğinden düzelsin.
/// </summary>
public sealed class RelayClock
{
    private long _lastRelayUtcTicks;   // 0 = henüz bildirim yok
    // Kayma, ÖLÇÜM ANINDA hesaplanıp saklanır: relayNow - enclaveNow.
    //
    // Sonradan "son bildirilen saat - şu anki saat" diye hesaplamak YANLIŞ olurdu; o fark
    // kaymayı değil, son bildirimden bu yana GEÇEN SÜREYİ ölçer. İlk canlı okumada tam bu
    // hatayı gördük: enclave senkronken ölçüm "39 saniye ileri" diyordu, çünkü relay 39 saniye
    // önce bildirmişti. Alarmı böyle bir sayının üstüne kurmak onu işe yaramaz yapardı.
    private long _lastDriftTicks;
    private bool _hasReport;

    /// <summary>Relay bir istekte saatini bildirdi (X-Relay-Time).</summary>
    public void Report(DateTimeOffset relayNow)
    {
        var ownNow = DateTime.UtcNow;
        Interlocked.Exchange(ref _lastRelayUtcTicks, relayNow.UtcTicks);
        Interlocked.Exchange(ref _lastDriftTicks, relayNow.UtcTicks - ownNow.Ticks);
        _hasReport = true;
    }

    /// <summary>En son bildirilen relay saati; hiç bildirilmediyse <c>null</c>.</summary>
    public DateTimeOffset? LastReported
    {
        get
        {
            var ticks = Interlocked.Read(ref _lastRelayUtcTicks);
            return ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    /// <summary>
    /// Kararlarda kullanılacak zaman: <c>max(enclave saati, relay saati)</c>.
    /// Relay hiç bildirmediyse enclave'in kendi saati.
    /// </summary>
    /// <remarks>
    /// Düzeltme, ÖLÇÜLEN KAYMA olarak uygulanır — son bildirilen mutlak zaman damgası olarak
    /// değil. Fark önemli: damga bildirim anında donar ve aradan geçen süre kadar geride kalır,
    /// oysa kayma sabit bir farktır ve bildirimler arasında da geçerliliğini korur.
    /// Negatif kayma (enclave ileride) SIFIRA kırpılır → saat asla geri gitmez.
    /// </remarks>
    public DateTime EffectiveUtcNow
    {
        get
        {
            var own = DateTime.UtcNow;
            if (!_hasReport) return own;
            var drift = Interlocked.Read(ref _lastDriftTicks);
            return drift > 0 ? own.AddTicks(drift) : own;
        }
    }

    /// <summary>Enclave saatinin relay saatinden ne kadar GERİ kaldığı (negatifse ileri).
    /// Teşhis/alarm için: bu değer büyümeye başlarsa saat kayması var demektir.</summary>
    public TimeSpan? DriftBehindRelay
        => _hasReport ? TimeSpan.FromTicks(Interlocked.Read(ref _lastDriftTicks)) : null;
}
