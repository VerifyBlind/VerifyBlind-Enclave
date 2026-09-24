using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services.Stance
{
    /// <summary>
    /// DURUŞ + OLAY DİZİSİ — nonce'tan deterministik olarak türetilir.
    ///
    /// <para><b>Neden rastgele üretip saklamak yerine türetiyoruz:</b> enclave durumsuz; el
    /// sıkışmada ürettiği diziyi register anında hatırlayamaz. Nonce ise enclave'in kendi
    /// imzaladığı ve register'da doğruladığı bir değer. Diziyi ondan türetmek, "istemcinin
    /// yaptığını söylediği" ile "sunucunun istediği"ni kıyaslamayı mümkün kılar. Eski jest
    /// dizisi <c>new Random()</c> ile üretiliyordu ve register anında neyin istendiği hiçbir
    /// yerde yoktu.</para>
    ///
    /// <para><b>Türetme herkese açık, bu bir zayıflık değil.</b> Kod açık kaynak; saldırgan
    /// nonce'u görünce diziyi hesaplayabilir. Ama nonce el sıkışmada zaten dizinin kendisiyle
    /// birlikte ona gönderiliyor — öğrendiği yeni bir şey yok. Nonce'u enclave kriptografik
    /// rastgeleyle üretir ve imzalar, istemci SEÇEMEZ. Yeni el sıkışmayla "kolay dizi" aramak
    /// mümkün ama bu her sunucu-rastgele tasarımda aynı; el sıkışma hız sınırlı.</para>
    ///
    /// <para><b>Kurallar</b> (kullanıcı kararları, 2026-09-24):</para>
    /// <list type="bullet">
    ///   <item>4 ya da 5 durak.</item>
    ///   <item>İlk durak YAKIN (çıpa): arka plan kısıtı yakın uçta bağlıyor; doku orada ölçülür.</item>
    ///   <item>Uzak, orta ve yakın her biri EN AZ BİR KEZ.</item>
    ///   <item>Ardışık iki durak aynı mesafede OLAMAZ — aralarında hareket olmalı.</item>
    ///   <item>Tam İKİ olay, iki FARKLI durakta, iki FARKLI türde. Kapsama = mesafe × olay
    ///     türü (saldırganın hazırlaması gereken klip sayısı); geçiş sayısı = olaylı durak
    ///     sayısı (canlı icra maliyeti). Her ek olay meşru kullanıcıda çarpımsal düşüş demek.</item>
    /// </list>
    /// </summary>
    public static class ChoreographyGenerator
    {
        public const int Version = 1;

        /// <summary>Alan ayrımı — aynı nonce'tan türetilen başka bir değerle (AA challenge) çakışmasın.</summary>
        private const string Domain = "vb-choreo-v1|";

        public const int MinStops = 4;
        public const int MaxStops = 5;
        public const int EventCount = 2;

        private static readonly StancePosition[] Positions =
            { StancePosition.Far, StancePosition.Mid, StancePosition.Near };

        private static readonly StanceEvent[] Events =
            { StanceEvent.Blink, StanceEvent.Smile, StanceEvent.MouthOpen, StanceEvent.DoubleBlink };

        public static Choreography FromNonce(string nonce)
        {
            ArgumentException.ThrowIfNullOrEmpty(nonce);
            var draw = new DeterministicDraw(
                SHA256.HashData(Encoding.UTF8.GetBytes(Domain + nonce)));

            // Reddetme örneklemesi: 4 duraklı dizilerin 6/8'i, 5 duraklıların 14/16'sı geçerli.
            // 64 deneme başarısızlık olasılığını fiilen sıfıra indirir; yine de sonsuz döngü
            // olmasın diye sınırlı.
            for (int attempt = 0; attempt < 64; attempt++)
            {
                int count = MinStops + draw.Next(MaxStops - MinStops + 1);

                var positions = new List<StancePosition>(count) { StancePosition.Near };
                while (positions.Count < count)
                {
                    var previous = positions[^1];
                    var options = Array.FindAll(Positions, p => p != previous);
                    positions.Add(options[draw.Next(options.Length)]);
                }

                if (!positions.Contains(StancePosition.Far) || !positions.Contains(StancePosition.Mid))
                    continue;

                int firstStop = draw.Next(count);
                int secondStop;
                do { secondStop = draw.Next(count); } while (secondStop == firstStop);

                int firstEvent = draw.Next(Events.Length);
                int secondEvent;
                do { secondEvent = draw.Next(Events.Length); } while (secondEvent == firstEvent);

                var choreography = new Choreography { Version = Version };
                for (int i = 0; i < count; i++)
                {
                    var ev = i == firstStop ? Events[firstEvent]
                        : i == secondStop ? Events[secondEvent]
                        : StanceEvent.None;
                    choreography.Stops.Add(new ChoreographyStop { Position = positions[i], Event = ev });
                }
                return choreography;
            }

            throw new InvalidOperationException("Koreografi üretilemedi — çekiliş kuralları çelişiyor.");
        }

        /// <summary>Teşhis için kısa biçim: <c>N,F+blink,M,N+smile</c>.</summary>
        public static string Describe(Choreography choreography)
        {
            var sb = new StringBuilder();
            foreach (var stop in choreography.Stops)
            {
                if (sb.Length > 0) sb.Append(',');
                sb.Append(stop.Position switch
                {
                    StancePosition.Far => 'F',
                    StancePosition.Mid => 'M',
                    _ => 'N',
                });
                if (stop.Event != StanceEvent.None) sb.Append('+').Append(EventName(stop.Event));
            }
            return sb.ToString();
        }

        public static string EventName(StanceEvent ev) => ev switch
        {
            StanceEvent.Blink => "blink",
            StanceEvent.Smile => "smile",
            StanceEvent.MouthOpen => "mouth_open",
            StanceEvent.DoubleBlink => "double_blink",
            _ => "none",
        };

        /// <summary>
        /// SHA-256 sayaç kipi ile deterministik, yansız tamsayı akışı.
        ///
        /// <para>Mod yanlılığı reddetme örneklemesiyle giderilir. Bu ölçekte (n ≤ 5) yanlılık
        /// zaten 2⁻³⁰ mertebesinde, ama dizi bir güvenlik parametresi ve yansız olduğunu
        /// göstermek, ihmal edilebilir olduğunu savunmaktan kolay.</para>
        /// </summary>
        private sealed class DeterministicDraw
        {
            private readonly byte[] _seed;
            private byte[] _block = Array.Empty<byte>();
            private int _offset;
            private uint _counter;

            public DeterministicDraw(byte[] seed) => _seed = seed;

            public int Next(int n)
            {
                if (n <= 0) throw new ArgumentOutOfRangeException(nameof(n));
                uint limit = uint.MaxValue - (uint.MaxValue % (uint)n);
                while (true)
                {
                    uint v = NextUInt();
                    if (v < limit) return (int)(v % (uint)n);
                }
            }

            private uint NextUInt()
            {
                if (_offset + 4 > _block.Length)
                {
                    var input = new byte[_seed.Length + 4];
                    Buffer.BlockCopy(_seed, 0, input, 0, _seed.Length);
                    BitConverter.TryWriteBytes(input.AsSpan(_seed.Length), _counter++);
                    _block = SHA256.HashData(input);
                    _offset = 0;
                }
                uint value = BitConverter.ToUInt32(_block, _offset);
                _offset += 4;
                return value;
            }
        }
    }
}
