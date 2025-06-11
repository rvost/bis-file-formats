﻿using BIS.Core.Streams;
using System;
using System.IO;

namespace BIS.Signatures.Wincrypt
{
    /// <summary>
    /// <see href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc">Docs</see>
    /// </summary>
    internal record KeyBlobHeader
    {
        internal enum BLOB_TYPE : byte
        {
            PUBLICKEYBLOB = 0x6,
            PRIVATEKEYBLOB = 0x7,
        }
        public BLOB_TYPE Type { get; set; }
        public byte Version { get; set; }
        public ushort Reserved { get; set; }
        public ALG_ID AlgId { get; set; }
        public uint BlobLength =>
           sizeof(byte) // Type
           + sizeof(byte) // Version
           + sizeof(ushort) // Reserved
           + sizeof(uint); // AlgId

        public static KeyBlobHeader GetRSAHeader(BLOB_TYPE type = BLOB_TYPE.PUBLICKEYBLOB) =>
            new()
            {
                Type = type,
                Version = 2,
                Reserved = 0,
                AlgId = ALG_ID.CALG_RSA_SIGN
            };

        public static KeyBlobHeader Read(BinaryReader reader)
        {
            var type = (BLOB_TYPE)reader.ReadByte();
            var version = reader.ReadByte();
            var reserved = reader.ReadUInt16();
            var algId = (ALG_ID)reader.ReadUInt32();
            return new()
            {
                Type = type,
                Version = version,
                Reserved = reserved,
                AlgId = algId
            };
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write((byte)Type);
            writer.Write(Version);
            writer.Write(Reserved);
            writer.Write((uint)AlgId);
        }
    }

    internal enum ALG_ID : uint
    {
        CALG_RSA_SIGN = 0x00002400,
    }
}
