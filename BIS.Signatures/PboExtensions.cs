using System;
using System.IO;
using System.Security.Cryptography;
using Pbo = BIS.PBO.PBO;

namespace BIS.Signatures
{
    public static class PboExtensions
    {

        public static byte[] CalculateChecksum(this Pbo pbo)
        {
            using var buffer = new MemoryStream();
            pbo.PBOFileStream.CopyTo(buffer);
            buffer.SetLength(buffer.Length - 21);
            buffer.Position = 0;

            using var sha = SHA1.Create();
            return sha.ComputeHash(buffer);
        }
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