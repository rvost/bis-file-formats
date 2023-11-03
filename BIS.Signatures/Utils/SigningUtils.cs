using System.IO;

namespace BIS.Signatures.Utils
{
    /// <summary>
    /// Provides static methods for resolving file names for BIS signatures and key files
    /// </summary>
    public class SigningUtils
    {
        /// <summary>
        /// Resolve the PBO signature file name for the given authority.
        /// </summary>
        /// <param name="authorityName">the name of the signing authority</param>
        /// <param name="pboName">the string containing the PBO file path</param>
        /// <returns>A string containing path of the signature file.</returns>
        public static string GetSignatureFileName(string authorityName, string pboName)
            => Path.ChangeExtension(pboName, $"pbo.{authorityName}.bisign");
        
        /// <summary>
        /// Resolve the PBO signature file name for the given authority.
        /// </summary>
        /// <param name="authorityName">the name of the signing authority</param>
        /// <param name="pboFile">the <c>FileInfo</c> wrapper of the PBO file</param>
        /// <returns>A <c>FileInfo</c> wrapper of the signature file.</returns>
        public static FileInfo GetSignatureFile(string authorityName, FileInfo pboFile)
            => new(GetSignatureFileName(authorityName, pboFile.FullName));

        /// <summary>
        /// Resolve public key file name for the given PBO signature.
        /// </summary>
        /// <param name="signatureFileName">the string containing path of the signature file</param>
        /// <returns>A string containing path of the public key file.</returns>
        public static string GetPublicKeyFileName(string signatureFileName)
        {
            var fileName = Path.GetFileName(signatureFileName);
            var authority = fileName.Substring(fileName.LastIndexOf('.'));
            return $"{authority}.bikey";
        }
    }
}
