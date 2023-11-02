using BIS.Core.Streams;
using BIS.Signatures.Wincrypt;
using System;
using System.IO;
using System.Linq;

namespace BIS.Signatures
{
    public record BiSign
    {
        private readonly CryptoApiBlob _sig1;
        private readonly CryptoApiBlob _sig2;
        private readonly CryptoApiBlob _sig3;

        public BiPublicKey PublicKey { get; private set; }
        public string Name => PublicKey.Name;
        public BiSignVersion Version { get; private set; }
        public byte[] Sig1 => _sig1.Data;
        public byte[] Sig2 => _sig2.Data;
        public byte[] Sig3 => _sig3.Data;

        public BiSign(BiSignVersion version, BiPublicKey key, byte[] sig1, byte[] sig2, byte[] sig3)
        {
            Version = version;
            PublicKey = key;
            _sig1 = new(sig1 ?? throw new ArgumentNullException(nameof(sig1)));
            _sig2 = new(sig2 ?? throw new ArgumentNullException(nameof(sig2)));
            _sig3 = new(sig3 ?? throw new ArgumentNullException(nameof(sig3)));
        }

        internal BiSign(BiSignVersion version, BiPublicKey key, CryptoApiBlob sig1, CryptoApiBlob sig2, CryptoApiBlob sig3)
        {
            Version = version;
            PublicKey = key;
            _sig1 = sig1 ?? throw new ArgumentNullException(nameof(sig1));
            _sig2 = sig2 ?? throw new ArgumentNullException(nameof(sig2));
            _sig3 = sig3 ?? throw new ArgumentNullException(nameof(sig3));
        }

        public static BiSign Read(BinaryReaderEx reader)
        {
            var key = BiPublicKey.Read(reader);
            var sig1 = CryptoApiBlob.Read(reader);
            var version = (BiSignVersion)reader.ReadUInt32();
            var sig2 = CryptoApiBlob.Read(reader);
            var sig3 = CryptoApiBlob.Read(reader);

            return new(version, key, sig1, sig2, sig3);
        }

        public static BiSign Read(Stream input) => Read(new BinaryReaderEx(input));

        public void Write(BinaryWriterEx writer)
        {
            PublicKey.Write(writer);
            _sig1.Write(writer);
            writer.Write((uint)Version);
            _sig2.Write(writer);
            _sig3.Write(writer);
        }

        public void Write(Stream output) => Write(new BinaryWriterEx(output));
    }
}
