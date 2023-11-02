using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BIS.Signatures.Wincrypt
{
    internal record CryptoApiBlob(byte[] Data)
    {
        public byte[] Data { get; private set; } = Data;

        public uint Length => (uint)Data.Length;

        public static CryptoApiBlob Read(BinaryReader reader)
        {
            var length = reader.ReadUInt32();
            var data = reader.ReadBytes((int)length);
            return new(data);
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write(Length);
            writer.Write(Data);
        }
    }
}
