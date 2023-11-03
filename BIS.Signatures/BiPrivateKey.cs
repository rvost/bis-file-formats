using BIS.Core.Streams;
using BIS.Signatures.Wincrypt;
using System;
using System.IO;
using System.Security.Cryptography;

namespace BIS.Signatures
{
    /// <summary>
    /// Represents BIS private key without the cryptographic implementation details.
    /// </summary>
    public record BiPrivateKey
    {
        /// <summary>
        /// The RSA public exponent is used in the BIS tools.
        /// </summary>
        public const uint DEFAULT_EXPONENT = 65537;
        /// <summary>
        /// The key length, in bits, used in the BIS tools.
        /// </summary>
        public const uint DEFAULT_LENGTH = 1024;

        private readonly uint _blobLength;
        private readonly KeyBlobHeader _keyHeader;
        private readonly RSAPrivateKeyBlob _key;

        /// <summary>
        /// Represent the name of the signing authority.
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// Represents the size of the key in <c>bits</c>.
        /// </summary>
        public uint BitLength => _key.BitLength;

        internal BiPrivateKey(string name, KeyBlobHeader header, RSAPrivateKeyBlob key)
        {
            Name = name;
            _blobLength = header.BlobLength + key.BlobLength;
            _keyHeader = header;
            _key = key;
        }

        /// <summary>
        /// Creates a new key with the specified parameters.
        /// </summary>
        /// <param name="name">the name of the signing authority.</param>
        /// <param name="length">the size of the key in bits.</param>
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

        /// <summary>
        /// Constructs a <c>BiPrivateKey</c> from the provided input.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Throws when the <c>BiPrivateKey</c> cannot be parsed from the input.
        /// </exception>
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

        /// <inheritdoc cref="Read(BinaryReaderEx)"/>
        public static BiPrivateKey Read(Stream input) => Read(new BinaryReaderEx(input));

        /// <summary>
        /// Writes the <c>BiPrivateKey</c> into the provided output in BIS format.
        /// </summary>
        public void Write(BinaryWriterEx writer)
        {
            writer.WriteAsciiz(Name);
            writer.Write(_blobLength);
            _keyHeader.Write(writer);
            _key.Write(writer);
        }

        /// <inheritdoc cref="Write(BinaryWriterEx)"/>
        public void Write(Stream output) => Write(new BinaryWriterEx(output));

        /// <summary>
        /// Creates a corresponding public key.
        /// </summary>
        public BiPublicKey ToPublicKey()
        {
            var header = KeyBlobHeader.GetRSAHeader();
            var key = RSAPublicKeyBlob.FromRSAPrivateKeyBlob(_key);
            return new(Name, header, key);
        }

        internal RSAParameters ToRSAParameters() => _key.ToRSAParameters();
    }
}
