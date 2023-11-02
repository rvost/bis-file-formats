using BIS.Core.Streams;
using BIS.Signatures.Wincrypt;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace BIS.Signatures
{
    public record BiPrivateKey
    {
        public const UInt32 DEFAULT_EXPONENT = 65537;
        public const UInt32 DEFAULT_LENGTH = 1024;

        private readonly uint _blobLength;
        private readonly KeyBlobHeader _keyHeader;
        private readonly RSAPrivateKeyBlob _key;

        public string Name { get; private set; }
        public uint BitLength => _key.BitLength;

        internal BiPrivateKey(string name, KeyBlobHeader header, RSAPrivateKeyBlob key)
        {
            Name = name;
            _blobLength = header.BlobLength + key.BlobLength;
            _keyHeader = header;
            _key = key;
        }

        public static BiPrivateKey Generate(string name, int length = (int)DEFAULT_LENGTH)
        {
            using var csp = new RSACryptoServiceProvider((int)length);
            try
            {
                var parameters = csp.ExportParameters(true);

                var header = KeyBlobHeader.GetRSAHeader(KeyBlobHeader.BLOB_TYPE.PRIVATEKEYBLOB);
                var key = RSAPrivateKeyBlob.FromRSAParameters(parameters);

                return new(name, header, key);
            }
            finally
            {
                csp.PersistKeyInCsp = false;
            }
        }

        public static BiPrivateKey Read(BinaryReaderEx reader)
        {
            var name = reader.ReadUTF8z();
            var blobLength = reader.ReadUInt32();

            var header = KeyBlobHeader.Read(reader);
            if (header.Type != KeyBlobHeader.BLOB_TYPE.PRIVATEKEYBLOB)
            {
                throw new InvalidOperationException();
            }

            var key = RSAPrivateKeyBlob.Read(reader);

            if (blobLength != header.BlobLength + key.BlobLength)
            {
                throw new InvalidOperationException();
            }

            return new(name, header, key);
        }

        public static BiPrivateKey Read(Stream input) => Read(new BinaryReaderEx(input));

        public void Write(BinaryWriterEx writer)
        {
            writer.WriteAsciiz(Name);
            writer.Write(_blobLength);
            _keyHeader.Write(writer);
            _key.Write(writer);
        }

        public void Write(Stream output) => Write(new BinaryWriterEx(output));

        public BiPublicKey ToPublicKey()
        {
            var header = KeyBlobHeader.GetRSAHeader();
            var key = RSAPublicKeyBlob.FromRSAPrivateKeyBlob(_key);
            return new(Name, header, key);
        }

        internal RSAParameters ToRSAParameters() => _key.ToRSAParameters();
    }
}
