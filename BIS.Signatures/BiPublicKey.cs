using BIS.Core.Streams;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace BIS.Signatures
{
    public record BiPublicKey
    {
        public string Name { get; private set; }

        public UInt32 Length { get; private set; }

        public UInt32 Exponent { get; private set; }

        public byte[] N { get; private set; }

        public BiPublicKey(string name, uint length, uint exponent, byte[] n)
        {
            Name = name;
            Length = length;
            Exponent = exponent;
            N = n;
        }

        private BiPublicKey()
        {

        }

        public static BiPublicKey Read(BinaryReaderEx reader)
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

            return new()
            {
                Name = name,
                Length = length,
                Exponent = exponent,
                N = n
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
        }

        internal RSAParameters ToRSAParameters() =>
            new()
            {
                Exponent = BiPrivateKey.EXPONENT_BYTES,
                Modulus = N
            };

        public static BiPublicKey FromSignature(BiSign signature)
        {
            return new()
            {
                Name = signature.Name,
                Length = signature.Length,
                Exponent = signature.Exponent,
                N = signature.N.ToArray()
            };
        }
    }
}
