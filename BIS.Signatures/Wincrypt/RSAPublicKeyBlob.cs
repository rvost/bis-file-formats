using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace BIS.Signatures.Wincrypt
{
    /// <summary>
    /// <see href="https://github.com/ashelmire/WinCryptoHelp">Reference</see>
    /// </summary>
    internal sealed class RSAPublicKeyBlob : IEquatable<RSAPublicKeyBlob>
    {
        public static uint SignAlgId => 0x31415352; // RSA1
        public uint BitLength { get; private set; }
        public uint PublicExponent { get; private set; }
        public byte[] Modulus { get; private set; }
        public uint BlobLength =>
            sizeof(uint) // SignAlgId
            + sizeof(uint) // BitLength
            + sizeof(uint) // PublicExponent
            + (uint)Modulus.Length;

        private RSAPublicKeyBlob(uint bitLength, uint publicExponent, byte[] modulus)
        {
            BitLength = bitLength;
            PublicExponent = publicExponent;
            Modulus = modulus;
        }

        public static RSAPublicKeyBlob FromRSAPrivateKeyBlob(RSAPrivateKeyBlob blob) =>
            new(blob.BitLength, blob.PublicExponent, blob.Modulus);

        public static RSAPublicKeyBlob FromRSAParameters(RSAParameters parameters)
        {
            var bitLength = (uint)parameters.Modulus.Length / 8;
            var exponent = BitConverter.ToUInt32(parameters.Exponent, 0);
            var modulus = parameters.Modulus.Reverse().ToArray();
            return new(bitLength, exponent, modulus);
        }

        public static RSAPublicKeyBlob Read(BinaryReader reader)
        {
            var signAlgId = reader.ReadUInt32();
            if (signAlgId != SignAlgId)
            {
                throw new InvalidOperationException();
            }
            var bitLength = reader.ReadUInt32();
            var publicExponent = reader.ReadUInt32();
            var modulus = reader.ReadBytes((int)bitLength / 8);
            return new(bitLength, publicExponent, modulus);
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write(SignAlgId);
            writer.Write(BitLength);
            writer.Write(PublicExponent);
            writer.Write(Modulus);
        }

        public RSAParameters ToRSAParameters() => new()
        {
            Exponent = BitConverter.GetBytes(PublicExponent),
            Modulus = Modulus.Reverse().ToArray(),
        };

        public override bool Equals(object obj)
        {
            return Equals(obj as RSAPublicKeyBlob);
        }

        public bool Equals(RSAPublicKeyBlob other)
        {
            return other is not null &&
                   BitLength == other.BitLength &&
                   PublicExponent == other.PublicExponent &&
                   Enumerable.SequenceEqual(Modulus, other.Modulus);
        }

        public override int GetHashCode()
        {
            int hashCode = 1475074757;
            hashCode = hashCode * -1521134295 + BitLength.GetHashCode();
            hashCode = hashCode * -1521134295 + PublicExponent.GetHashCode();
            hashCode = hashCode * -1521134295 + ComputeHash(Modulus);
            return hashCode;
        }

        private static int ComputeHash(params byte[] data)
        {
            unchecked
            {
                const int p = 16777619;
                int hash = (int)2166136261;

                for (int i = 0; i < data.Length; i++)
                    hash = (hash ^ data[i]) * p;

                return hash;
            }
        }
    }
}
