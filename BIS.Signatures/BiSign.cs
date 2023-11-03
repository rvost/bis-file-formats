using BIS.Core.Streams;
using BIS.Signatures.Wincrypt;
using System;
using System.IO;

namespace BIS.Signatures
{
    /// <summary>
    /// Represents BIS PBO signature.
    /// </summary>
    public record BiSign
    {
        private readonly CryptoApiBlob _sig1;
        private readonly CryptoApiBlob _sig2;
        private readonly CryptoApiBlob _sig3;

        /// <summary>
        /// Represents the public key of the signing authority.
        /// </summary>
        public BiPublicKey PublicKey { get; private set; }
        /// <summary>
        /// Represent the name of the signing authority.
        /// </summary>
        public string Name => PublicKey.Name;
        /// <summary>
        /// Represents version of the algorithm that was used to generate the signature.
        /// </summary>
        public BiSignVersion Version { get; private set; }
        /// <summary>
        /// Represents the signature of the PBO checksum.
        /// </summary>
        public byte[] Sig1 => _sig1.Data;
        /// <summary>
        /// Represents the second signature.
        /// <para>
        /// The signature is computed from the combined PBO checksum and file name hashes, as well as the prefix.
        /// </para>
        /// </summary>
        public byte[] Sig2 => _sig2.Data;
        /// <summary>
        /// Represents the third signature.
        /// <para>
        /// The computation of the hash used for the signature depends on the version of the signing algorithm.
        /// </para>
        /// </summary>
        public byte[] Sig3 => _sig3.Data;

        /// <summary>
        /// Constructs <c>BiSign</c> from the specified parameters.
        /// </summary>
        /// <param name="version">the version of the signing algorithm</param>
        /// <param name="key">the public key of the signing authority</param>
        /// <param name="sig1">the signed PBO checksum</param>
        /// <param name="sig2">the second signed hash</param>
        /// <param name="sig3">the third signed hash</param>
        /// <exception cref="ArgumentNullException"></exception>
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

        /// <summary>
        /// Constructs a <c>BiSign</c> from the provided input.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Throws when the <c>BiSign</c> cannot be parsed from the input.
        /// </exception>
        public static BiSign Read(BinaryReaderEx reader)
        {
            var key = BiPublicKey.Read(reader);
            var sig1 = CryptoApiBlob.Read(reader);
            var version = (BiSignVersion)reader.ReadUInt32();
            var sig2 = CryptoApiBlob.Read(reader);
            var sig3 = CryptoApiBlob.Read(reader);

            return new(version, key, sig1, sig2, sig3);
        }

        /// <inheritdoc cref="Read(BinaryReaderEx)"/>
        public static BiSign Read(Stream input) => Read(new BinaryReaderEx(input));

        /// <summary>
        /// Writes the <c>BiSign</c> into the provided output.
        /// </summary>
        public void Write(BinaryWriterEx writer)
        {
            PublicKey.Write(writer);
            _sig1.Write(writer);
            writer.Write((uint)Version);
            _sig2.Write(writer);
            _sig3.Write(writer);
        }

        /// <inheritdoc cref="Write(BinaryWriterEx)"/>
        public void Write(Stream output) => Write(new BinaryWriterEx(output));
    }
}
