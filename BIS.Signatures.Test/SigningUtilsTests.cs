using BIS.Signatures.Utils;

namespace BIS.Signatures.Test
{
    public class SigningUtilsTests
    {
        [Fact]
        public void CanGetSignatureFileNameForPbo()
        {
            var pboName = "Resources\\Test_Tank_01.pbo";
            var authority = "FooBar";
            var expected = $"{pboName}.{authority}.bisign";

            var actual = SigningUtils.GetSignatureFileName(authority, pboName);

            Assert.Equal(expected, actual);
        }
    }
}
