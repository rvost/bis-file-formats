using BIS.Signatures.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Pbo = BIS.PBO.PBO;

namespace BIS.Signatures
{
    /// <summary>
    /// Provides static methods for signing and verifying PBO signatures.
    /// </summary>
    public static class Signing
    {
        /// <summary>
        /// Generates a signature for the PBO file.
        /// </summary>
        /// <param name="key">the private key of the signing authority</param>
        /// <param name="version">the version of the signing algorithm</param>
        /// <param name="pbo">the PBO file to sign</param>
        /// <returns></returns>
        public static BiSign Sign(BiPrivateKey key, BiSignVersion version, Pbo pbo)
        {
            var (hash1, hash2, hash3) = GetPboHashes(version, pbo);

            using var rsa = RSA.Create();
            var p = key.ToRSAParameters();
            rsa.ImportParameters(p);

            // Manged cryptography uses Big Endian, but the signatures are stored in Little Endian order
            var sig1 = rsa.SignHash(hash1, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            Array.Reverse(sig1);
            var sig2 = rsa.SignHash(hash2, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            Array.Reverse(sig2);
            var sig3 = rsa.SignHash(hash3, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            Array.Reverse(sig3);

            return new BiSign(
                version,
                key.ToPublicKey(),
                sig1,
                sig2,
                sig3
                );
        }

        /// <summary>
        /// Verify the PBO signature using the provided public key.
        /// </summary>
        /// <param name="key">the public key of the signing authority</param>
        /// <param name="signature">the signature to verify</param>
        /// <param name="pbo">the PBO file to verify</param>
        /// <returns>Returns wether verification was succesfull</returns>
        public static bool Verify(BiPublicKey key, BiSign signature, Pbo pbo)
        {
            var (hash1, hash2, hash3) = GetPboHashes(signature.Version, pbo);

            using var rsa = RSA.Create();
            var p = key.ToRSAParameters();
            rsa.ImportParameters(p);

            // Manged cryptography uses Big Endian, but the signatures are stored in Little Endian order
            var b1 = rsa.VerifyHash(hash1, signature.Sig1.Reverse().ToArray(), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            var b2 = rsa.VerifyHash(hash2, signature.Sig2.Reverse().ToArray(), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            var b3 = rsa.VerifyHash(hash3, signature.Sig3.Reverse().ToArray(), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            return b1 && b2 && b3;
        }
        
        /// <summary>
        /// Verify the PBO signature.
        /// </summary>
        /// <param name="signature">the signature to verify</param>
        /// <param name="pbo">the PBO file to verify</param>
        /// <returns>Returns wether verification was succesfull</returns>
        public static bool Verify(BiSign signature, Pbo pbo) => Verify(signature.PublicKey, signature, pbo);
        /// <summary>
        /// Verify the PBO signature using the set of allowed authorities
        /// </summary>
        /// <param name="allowedKeys">the public keys of allowed signing authorities</param>
        /// <param name="signature">the signature to verify</param>
        /// <param name="pbo">the PBO file to verify</param>
        /// <returns></returns>
        public static bool Verify(HashSet<BiPublicKey> allowedKeys, BiSign signature, Pbo pbo)
            => allowedKeys.Contains(signature.PublicKey) && Verify(signature.PublicKey, signature, pbo);

        private static byte[] ComputeCombinedHash(params byte[][] data)
        {
            var position = 0;
            var buffer = new byte[data.Sum(a => a.Length)];
            foreach (var curr in data)
            {
                Array.Copy(curr, 0, buffer, position, curr.Length);
                position += curr.Length;
            }

            using var sha = SHA1.Create();
            return sha.ComputeHash(buffer);
        }

        private static (byte[], byte[], byte[]) GetPboHashes(BiSignVersion version, Pbo pbo)
        {
            var prefix = PboUtils.GetPrefixBytes(pbo);
            var nameHash = PboUtils.HashFileNames(pbo);
            var fileHash = PboUtils.HashFiles(version, pbo);

            var hash1 = pbo.ReadChecksum();
            var hash2 = ComputeCombinedHash(hash1, nameHash, prefix);
            var hash3 = ComputeCombinedHash(fileHash, nameHash, prefix);

            return (hash1, hash2, hash3);
        }

    }
}
