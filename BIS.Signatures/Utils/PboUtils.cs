using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Pbo = BIS.PBO.PBO;

namespace BIS.Signatures.Utils
{
    internal static class PboUtils
    {
        internal static byte[] HashFileNames(Pbo pbo)
        {
            var filenames = pbo.Files
                .Select(x => x.FileName.ToLower())
                .Where(s => !string.IsNullOrWhiteSpace(s));

            var buffer = string.Join("", filenames).ToCharArray();

            using var sha = SHA1.Create();
            return sha.ComputeHash(Encoding.ASCII.GetBytes(buffer));
        }

        internal static byte[] HashFiles(BiSignVersion version, Pbo pbo)
        {
            var files = pbo.Files
                .Where(f => ShouldHashFile(version, f.FileName))
                .OrderBy(f => f.FileName)
                .ToList();
            
            using var sha = SHA1.Create();

            if (files.Any())
            {
                var buffer = new MemoryStream();
                files.ForEach(file =>
                {
                    using var fs = file.OpenRead();
                    fs.CopyTo(buffer);
                });
                buffer.Position = 0;
                return sha.ComputeHash(buffer);
            }
            else
            {
                var nothing = version switch
                {
                    BiSignVersion.V2 => "nothing",
                    BiSignVersion.V3 => "gnihton"
                };

                return sha.ComputeHash(Encoding.ASCII.GetBytes(nothing));
            }
        }

        internal static byte[] GetPrefixBytes(Pbo pbo)
        {
            var prefix = pbo.Prefix;
            
            if(string.IsNullOrEmpty(prefix))
            {
                return Array.Empty<byte>();
            }

            if (!prefix.EndsWith(@"\"))
            {
                prefix += @"\";
            }

            return Encoding.ASCII.GetBytes(prefix);
        }

        private static bool ShouldHashFile(BiSignVersion version, string file)
        {
            var v2exceptions = new HashSet<string>() 
            {
                ".fxy", ".jpg", ".lip", ".ogg", ".p3d", ".paa", ".pac", ".png", ".rtm", ".rvmat",
                ".tga", ".wrp", ".wss"
            };

            var extsV3 = new HashSet<string>()
            {
                ".bikb", ".cfg", ".ext", ".fsm", ".h", ".hpp", ".inc", ".sqf", ".sqfc",
                ".sqm", ".sqs"
            };

            var ext = Path.GetExtension(file);

            switch (version)
            {
                case BiSignVersion.V2:
                    return !v2exceptions.Contains(ext);
                case BiSignVersion.V3:
                    return extsV3.Contains(ext);
                default:
                    throw new InvalidOperationException("Invalid BiSign version");
            }
        }
    }
}