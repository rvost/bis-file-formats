using System;
using System.Linq;
using BIS.Core.Config;

namespace BIS.PBO
{
    public static class PBOExtensions
    {
        public static ParamFile ReadAsConfig(this IPBOFileEntry entry)
        {
            using (var stream = entry.OpenRead())
            {
                return new ParamFile(stream);
            }
        }

        public static ParamFile GetRootConfig(this PBO pbo)
        {
            var configEntry = pbo.Files.FirstOrDefault(f => string.Equals(f.FileName, "config.bin", StringComparison.OrdinalIgnoreCase));
            if (configEntry != null)
            {
                return configEntry.ReadAsConfig();
            }
            return null;
        }
    }
}
