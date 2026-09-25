using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using VerifyBlind.Core.Models;

namespace VerifyBlind.Enclave.Services.Liveness
{
    /// <summary>
    /// OLAY DİZİSİ — nonce'tan deterministik olarak türetilir.
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
    /// <para><b>Kurallar</b> (kullanıcı kararları, 2026-09-25):</para>
    /// <list type="bullet">
    ///   <item>Tek mesafe — mesafe değişimine dayanan her yöntem kaldırıldı (patent riski).</item>
    ///   <item>Dört hareketten ÜÇÜ, hepsi FARKLI, rastgele sırada: 24 olası dizi. Saldırganın
    ///     kayıttan sunması için dört hareketin de klibi ve sırayı o an kurması gerekir. Her ek
    ///     hareket meşru kullanıcıda çarpımsal düşüş demek; üç, ikisinin dengesi.</item>
    /// </list>
    ///
    /// <para>Sürüm 1 (uzak/orta/yakın duraklar) kaldırıldı; türetme alanı sürümle değişir ki
    /// eski bir nonce'tan yeni biçimde dizi çıkmasın.</para>
    /// </summary>
    public static class ChoreographyGenerator
    {
        public const int Version = 2;

        /// <summary>Alan ayrımı — aynı nonce'tan türetilen başka bir değerle (AA challenge) çakışmasın.</summary>
        private const string Domain = "vb-choreo-v2|";

        public const int EventCount = 3;

        private static readonly LivenessEvent[] Events =
            { LivenessEvent.Blink, LivenessEvent.Smile, LivenessEvent.MouthOpen, LivenessEvent.DoubleBlink };

        public static Choreography FromNonce(string nonce)
        {
            ArgumentException.ThrowIfNullOrEmpty(nonce);
            var draw = new DeterministicDraw(
                SHA256.HashData(Encoding.UTF8.GetBytes(Domain + nonce)));

            // Fisher-Yates'in ilk EventCount adımı: tekrarsız, yansız bir sıralı seçim.
            var pool = new List<LivenessEvent>(Events);
            var choreography = new Choreography { Version = Version };
            for (int i = 0; i < EventCount; i++)
            {
                int pick = draw.Next(pool.Count);
                choreography.Events.Add(pool[pick]);
                pool.RemoveAt(pick);
            }
            return choreography;
        }

        /// <summary>Teşhis için kısa biçim: <c>blink,mouth_open,smile</c>.</summary>
        public static string Describe(Choreography choreography) =>
            string.Join(",", choreography.Events.ConvertAll(EventName));

        public static string EventName(LivenessEvent ev) => ev switch
        {
            LivenessEvent.Blink => "blink",
            LivenessEvent.Smile => "smile",
            LivenessEvent.MouthOpen => "mouth_open",
            LivenessEvent.DoubleBlink => "double_blink",
            _ => "none",
        };

        /// <summary>Olayın kaç kare istediği — çift kırpmada iki kapanma, diğerlerinde bir an.</summary>
        public static int FramesFor(LivenessEvent ev) => ev == LivenessEvent.DoubleBlink ? 2 : 1;

        /// <summary>
        /// SHA-256 sayaç kipi ile deterministik, yansız tamsayı akışı.
        ///
        /// <para>Mod yanlılığı reddetme örneklemesiyle giderilir. Bu ölçekte (n ≤ 4) yanlılık
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
