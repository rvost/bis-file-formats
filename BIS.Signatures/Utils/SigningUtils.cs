using System.IO;

namespace BIS.Signatures.Utils
{
    public class SigningUtils
    {
        public static string GetSignatureFileName(string authorityName, string pboName)
            => Path.ChangeExtension(pboName, $"pbo.{authorityName}.bisign");
        public static FileInfo GetSignatureFile(string authorityName, FileInfo pboFile)
            => new(GetSignatureFileName(authorityName, pboFile.FullName));

        public static string GetPublicKeyFileName(string signatureFileName)
        {
            var fileName = Path.GetFileName(signatureFileName);
            var authority = fileName.Substring(fileName.LastIndexOf('.'));
            return $"{authority}.bikey";
        }
    }
}
