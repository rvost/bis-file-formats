using System;
using System.IO;
using System.Security.Cryptography;
using Pbo = BIS.PBO.PBO;

namespace BIS.Signatures
{
    /// <summary>
    /// Provides extension methods for reading and calculating the checksums of <see cref="BIS.PBO.PBO"/>
    /// </summary>
    public static class PboExtensions
    {
        /// <summary>
        /// Calculates PBO checksum.
        /// <para>
        /// The SHA-1 hash of the file content is used as the checksum.
        /// </para>
        /// </summary>
        /// <param name="pbo"></param>
        /// <returns>The computed checksum</returns>
        public static byte[] CalculateChecksum(this Pbo pbo)
        {
            using var buffer = new MemoryStream();
            pbo.PBOFileStream.CopyTo(buffer);
            buffer.SetLength(buffer.Length - 21);
            buffer.Position = 0;

            using var sha = SHA1.Create();
            return sha.ComputeHash(buffer);
        }

        /// <summary>
        /// Reads PBO checksum from the file.
        /// </summary>
        /// <param name="pbo"></param>
        /// <returns>The PBO checksum</returns>
        /// <exception cref="InvalidOperationException">Throws when the file does not contain a checksum.</exception>
        public static byte[] ReadChecksum(this Pbo pbo)
        {
            var fs = pbo.PBOFileStream;

            var pos = fs.Position;
            fs.Seek(-21, System.IO.SeekOrigin.End);
            var check = fs.ReadByte();
            var buffer = new byte[20];
            fs.Read(buffer, 0, 20);
            fs.Position = pos;

            if (check == 0)
            {
                return buffer;
            }
            else
            {
                // TODO: Use domain exception
                throw new InvalidOperationException("PBO file does not contain signature");
            }
        }
    }
}