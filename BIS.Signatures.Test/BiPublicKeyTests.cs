using BIS.Core.Streams;
using System.Security.Cryptography;

namespace BIS.Signatures.Test
{
    public class BiPublicKeyTests
    {
        [Fact]
        public void CanRead()
        {
            var input = File.OpenRead(@"Resources\Test.bikey");
            var reader = new BinaryReaderEx(input);

            var key = BiPublicKey.Read(reader);

            Assert.NotNull(key);
            Assert.Equal("Test", key.Name);
        }

        [Fact]
        public void CanWrite()
        {
            var input = File.OpenRead(@"Resources\Test.bikey");
            var expected = new MemoryStream();
            input.CopyTo(expected);
            input.Position = 0;
            var reader = new BinaryReaderEx(input);
            var key = BiPublicKey.Read(reader);

            var output = new MemoryStream();
            var writer = new BinaryWriterEx(output);
            key.Write(writer);

            TestsHelpers.AssertStreamsEqual(expected, output);
        }

        [Fact]
        public void CanExportParameters()
        {
            var input = File.OpenRead(@"Resources\Test.bikey");
            var reader = new BinaryReaderEx(input);
            var key = BiPublicKey.Read(reader);

            var parameters = key.ToRSAParameters();
            using var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
        }

        [Fact]
        public void KeysAreStructurallyEqual()
        {
            var keyInput = File.OpenRead(@"Resources\Test.bikey");
            var keyReader = new BinaryReaderEx(keyInput);
            var key = BiPublicKey.Read(keyReader);

            var signInput = File.OpenRead(@"Resources\test.pbo.Test.bisign");
            var signReader = new BinaryReaderEx(signInput);
            var sign = BiSign.Read(signReader);

            Assert.Equal(key.GetHashCode(), sign.PublicKey.GetHashCode());
            Assert.Equal(key, sign.PublicKey);
        }
    }
}
