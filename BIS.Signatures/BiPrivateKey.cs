using BIS.Core.Streams;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace BIS.Signatures
{
    public record BiPrivateKey
    {
        public const UInt32 EXPONENT = 65537;
        public const UInt32 LENGTH = 1024;
        internal static readonly byte[] EXPONENT_BYTES = new byte[] { 1, 0, 1 };

        public string Name { get; private set; }

        public UInt32 Length { get; private set; }

        public UInt32 Exponent { get; private set; }

        public byte[] N { get; private set; }

        public byte[] P { get; private set; }

        public byte[] Q { get; private set; }

        public byte[] DP { get; private set; }

        public byte[] DQ { get; private set; }

        public byte[] InverseQ { get; private set; }

        public byte[] D { get; private set; }

        public static BiPrivateKey Generate(string name, UInt32 length = 1024)
        {
            using var csp = new RSACryptoServiceProvider((int)length);
            try
            {
                var parameters = csp.ExportParameters(true);

                return new()
                {
                    Name = name,
                    Length = length,
                    Exponent = EXPONENT,
                    N = parameters.Modulus,
                    P = parameters.P,
                    Q = parameters.Q,
                    DP = parameters.DP,
                    DQ = parameters.DQ,
                    InverseQ = parameters.InverseQ,
                    D = parameters.D,
                };
            }
            finally
            {
                csp.PersistKeyInCsp = false;
            }
        }

        public static BiPrivateKey Read(BinaryReaderEx reader)
        {
            var name = reader.ReadUTF8z();
            var temp = reader.ReadUInt32();

            // unknown
            reader.ReadUInt32();
            reader.ReadUInt32();
            reader.ReadUInt32();

            var length = reader.ReadUInt32();
            var exponent = reader.ReadUInt32();

            if (temp != length / 16 * 9 + 20)
            {
                throw new InvalidOperationException();
            }

            var n = reader.ReadBytes((int)length / 8).Reverse().ToArray();
            var p = reader.ReadBytes((int)length / 16).Reverse().ToArray();
            var q = reader.ReadBytes((int)length / 16).Reverse().ToArray();

            var dp = reader.ReadBytes((int)length / 16).Reverse().ToArray();
            var dq = reader.ReadBytes((int)length / 16).Reverse().ToArray();
            var invq = reader.ReadBytes((int)length / 16).Reverse().ToArray();

            var d = reader.ReadBytes((int)length / 8).Reverse().ToArray();

            return new()
            {
                Name = name,
                Length = length,
                Exponent = exponent,
                N = n,
                P = p,
                Q = q,
                DP = dp,
                DQ = dq,
                InverseQ = invq,
                D = d
            };
        }

        public void Write(BinaryWriterEx writer)
        {
            writer.WriteAsciiz(Name);
            writer.Write(Length / 16 * 9 + 20);

            // TODO: Use UTF-8 string literals after update to C# 11 
            var unknown = new byte[] { 0x07, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00 };
            var rsa = new byte[] { 0x52, 0x53, 0x41, 0x32 }; // "RSA2"
            writer.Write(unknown);
            writer.Write(rsa);

            writer.Write(Length);
            writer.Write(Exponent);
            writer.Write(N.Reverse().ToArray());
            writer.Write(P.Reverse().ToArray());
            writer.Write(Q.Reverse().ToArray());
            writer.Write(DP.Reverse().ToArray());
            writer.Write(DQ.Reverse().ToArray());
            writer.Write(InverseQ.Reverse().ToArray());
            writer.Write(D.Reverse().ToArray());
        }

        public BiPublicKey ToPublicKey() => new(Name, Length, Exponent, N.ToArray());

        internal RSAParameters ToRSAParameters() =>
            new()
            {
                Exponent = EXPONENT_BYTES,
                Modulus = N,
                D = D,
                P = P,
                Q = Q,
                DP = DP,
                DQ = DQ,
                InverseQ = InverseQ
            }; 
    }
}
