using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace BIS.Signatures.Wincrypt
{
    /// <summary>
    /// <see href="https://github.com/ashelmire/WinCryptoHelp">Reference</see>
    /// </summary>
    internal sealed class RSAPrivateKeyBlob
    {
        static uint SignAlgId => 0x32415352; // RSA2
        public uint BitLength { get; private set; }
        public uint PublicExponent { get; private set; }
        public byte[] Modulus { get; private set; }
        public byte[] Prime1 { get; private set; }
        public byte[] Prime2 { get; private set; }
        public byte[] Exponent1 { get; private set; }
        public byte[] Exponent2 { get; private set; }
        public byte[] Coefficient { get; private set; }
        public byte[] PrivateExponent { get; private set; }
        public uint BlobLength =>
            sizeof(uint) // SignAlgId
            + sizeof(uint) // BitLength
            + sizeof(uint) // PublicExponent
            + (uint)Modulus.Length
            + (uint)Prime1.Length
            + (uint)Prime2.Length
            + (uint)Exponent1.Length
            + (uint)Exponent2.Length
            + (uint)Coefficient.Length
            + (uint)PrivateExponent.Length;

        private RSAPrivateKeyBlob()
        {

        }

        public static RSAPrivateKeyBlob FromRSAParameters(RSAParameters parameters)
        {
            var bitLength = (uint)parameters.Modulus.Length * 8;
            var buffer = new byte[4];
            parameters.Exponent.CopyTo(buffer, 0);
            var exponent = BitConverter.ToUInt32(buffer, 0);
            return new()
            {
                BitLength = bitLength,
                PublicExponent = exponent,
                Modulus = parameters.Modulus.Reverse().ToArray(),
                Prime1 = parameters.P.Reverse().ToArray(),
                Prime2 = parameters.Q.Reverse().ToArray(),
                Exponent1 = parameters.DP.Reverse().ToArray(),
                Exponent2 = parameters.DQ.Reverse().ToArray(),
                Coefficient = parameters.InverseQ.Reverse().ToArray(),
                PrivateExponent = parameters.D.Reverse().ToArray()
            };
        }

        public static RSAPrivateKeyBlob Read(BinaryReader reader)
        {
            var signAlgId = reader.ReadUInt32();
            if (signAlgId != SignAlgId)
            {
                throw new InvalidOperationException();
            }
            var bitLength = reader.ReadUInt32();
            var byteLength = (int)bitLength / 8;
            var publicExponent = reader.ReadUInt32();
            var modulus = reader.ReadBytes(byteLength);
            var prime1 = reader.ReadBytes(byteLength / 2);
            var prime2 = reader.ReadBytes(byteLength / 2);
            var exponent1 = reader.ReadBytes(byteLength / 2);
            var exponent2 = reader.ReadBytes(byteLength / 2);
            var coefficient = reader.ReadBytes(byteLength / 2);
            var privateExponent = reader.ReadBytes(byteLength);
            return new()
            {
                BitLength = bitLength,
                PublicExponent = publicExponent,
                Modulus = modulus,
                Prime1 = prime1,
                Prime2 = prime2,
                Exponent1 = exponent1,
                Exponent2 = exponent2,
                Coefficient = coefficient,
                PrivateExponent = privateExponent
            };
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write(SignAlgId);
            writer.Write(BitLength);
            writer.Write(PublicExponent);
            writer.Write(Modulus);
            writer.Write(Prime1);
            writer.Write(Prime2);
            writer.Write(Exponent1);
            writer.Write(Exponent2);
            writer.Write(Coefficient);
            writer.Write(PrivateExponent);
        }

        public RSAParameters ToRSAParameters() => new()
        {
            Exponent = BitConverter.GetBytes(PublicExponent).Take(3).ToArray(),
            Modulus = Modulus.Reverse().ToArray(),
            P = Prime1.Reverse().ToArray(),
            Q = Prime2.Reverse().ToArray(),
            DP = Exponent1.Reverse().ToArray(),
            DQ = Exponent2.Reverse().ToArray(),
            InverseQ = Coefficient.Reverse().ToArray(),
            D = PrivateExponent.Reverse().ToArray(),
        };
    }
}
