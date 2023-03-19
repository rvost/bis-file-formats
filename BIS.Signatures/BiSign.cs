using BIS.Core.Streams;
using System;
using System.Linq;

namespace BIS.Signatures
{
    public record BiSign
    {
        public BiSignVersion Version { get; private set; }
        public string Name { get; private set; }

        public UInt32 Length { get; private set; }

        public UInt32 Exponent { get; private set; }

        public byte[] N { get; private set; }

        public byte[] Sig1 { get; private set; }

        public byte[] Sig2 { get; private set; }

        public byte[] Sig3 { get; private set; }

        public BiSign(BiSignVersion version, string name, uint length, uint exponent, byte[] n, byte[] sig1, byte[] sig2, byte[] sig3)
        {
            Version = version;
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Length = length;
            Exponent = exponent;
            N = n ?? throw new ArgumentNullException(nameof(n));
            Sig1 = sig1 ?? throw new ArgumentNullException(nameof(sig1));
            Sig2 = sig2 ?? throw new ArgumentNullException(nameof(sig2));
            Sig3 = sig3 ?? throw new ArgumentNullException(nameof(sig3));
        }

        private BiSign() { }

        public static BiSign Read(BinaryReaderEx reader)
        {
            var name = reader.ReadUTF8z();
            var temp = reader.ReadUInt32();

            // unknown
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();

            var length = reader.ReadUInt32();
            var exponent = reader.ReadUInt32();

            if (temp != length / 8 + 20)
            {
                throw new InvalidOperationException();
            }

            var n = reader.ReadBytes((int)length / 8).Reverse().ToArray();

            reader.ReadUInt32();
            var sig1 = reader.ReadBytes((int)length / 8).Reverse().ToArray();

            var version = (BiSignVersion)reader.ReadUInt32();

            reader.ReadUInt32();
            var sig2 = reader.ReadBytes((int)length / 8).Reverse().ToArray();

            reader.ReadUInt32();
            var sig3 = reader.ReadBytes((int)length / 8).Reverse().ToArray();

            return new()
            {
                Version = version,
                Name = name,
                Length = length,
                Exponent = exponent,
                N = n,
                Sig1 = sig1,
                Sig2 = sig2,
                Sig3 = sig3
            };
        }

        public void Write(BinaryWriterEx writer)
        {
            writer.WriteAsciiz(Name);
            writer.Write(Length / 8 + 20);

            // TODO: Use UTF-8 string literals after update to C# 11 
            var unknown = new byte[] { 0x06, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00 };
            var rsa = new byte[] { 0x52, 0x53, 0x41, 0x31 }; // "RSA1"
            writer.Write(unknown);
            writer.Write(rsa);

            writer.Write(Length);
            writer.Write(Exponent);
            writer.Write(N.Reverse().ToArray());
            writer.Write(Length / 8);
            writer.Write(Sig1.Reverse().ToArray());
            writer.Write((UInt32)Version);
            writer.Write(Length / 8);
            writer.Write(Sig2.Reverse().ToArray());
            writer.Write(Length / 8);
            writer.Write(Sig3.Reverse().ToArray());
        }

        public BiPublicKey ToPublicKey() => new(Name, Length, Exponent, N.ToArray());

    }
}
