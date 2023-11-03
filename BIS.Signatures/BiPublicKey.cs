using BIS.Core.Streams;
using BIS.Signatures.Wincrypt;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace BIS.Signatures
{
    /// <summary>
    /// Represents BIS public key without the cryptographic implementation details.
    /// </summary>
    public record BiPublicKey
    {
        private readonly uint _blobLength;
        private readonly KeyBlobHeader _keyHeader;
        private readonly RSAPublicKeyBlob _key;

        /// <summary>
        /// Represent the name of the signing authority.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Represents the size of the key in <c>bits</c>.
        /// </summary>
        public uint BitLength => _key.BitLength;

        internal BiPublicKey(string name, KeyBlobHeader header, RSAPublicKeyBlob key)
        {
            Name = name;
            _blobLength = header.BlobLength + key.BlobLength;
            _keyHeader = header;
            _key = key;
        }

        /// <summary>
        /// Constructs a <c>BiPublicKey</c> from the provided input.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Throws when the <c>BiPublicKey</c> cannot be parsed from the input.
        /// </exception>
        public static BiPublicKey Read(BinaryReaderEx reader)
        {
            var name = reader.ReadUTF8z();

            var length = reader.ReadUInt32();
            var header = KeyBlobHeader.Read(reader);
            if (header.Type != KeyBlobHeader.BLOB_TYPE.PUBLICKEYBLOB)
            {
                throw new InvalidOperationException();
            }

            var key = RSAPublicKeyBlob.Read(reader);

            if (length != header.BlobLength + key.BlobLength)
            {
                throw new InvalidOperationException();
            }

            return new(name, header, key);
        }

        /// <inheritdoc cref="Read(BinaryReaderEx)"/>
        public static BiPublicKey Read(Stream input) => Read(new BinaryReaderEx(input));

        /// <summary>
        /// Writes the <c>BiPublicKey</c> into the provided output in BIS format.
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

        internal RSAParameters ToRSAParameters() =>
            new()
            {
                Exponent = BitConverter.GetBytes(_key.PublicExponent).Take(3).ToArray(),
                Modulus = _key.Modulus.Reverse().ToArray(),
            };
    }
}
