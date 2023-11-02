using BIS.Signatures.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Pbo = BIS.PBO.PBO;

namespace BIS.Signatures
{
    public static class Signing
    {
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

        public static bool Verify(BiSign signature, Pbo pbo) => Verify(signature.PublicKey, signature, pbo);
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
