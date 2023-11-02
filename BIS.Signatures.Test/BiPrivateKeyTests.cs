using BIS.Core.Streams;
using System.Security.Cryptography;

namespace BIS.Signatures.Test
{
    public class BiPrivateKeyTests
    {
        [Fact]
        public void CanRead()
        {
            var input = File.OpenRead(@"Resources\Test.biprivatekey");
            using var reader = new BinaryReaderEx(input);

            var key = BiPrivateKey.Read(reader);

            Assert.NotNull(key);
            Assert.Equal("Test", key.Name);
        }

        [Fact]
        public void CanWrite()
        {
            var input = File.OpenRead(@"Resources\Test.biprivatekey");
            var expected = new MemoryStream();
            input.CopyTo(expected);
            input.Position = 0;
            using var reader = new BinaryReaderEx(input);
            var key = BiPrivateKey.Read(reader);

            var output = new MemoryStream();
            var writer = new BinaryWriterEx(output);
            key.Write(writer);

            TestsHelpers.AssertStreamsEqual(expected, output);
        }

        [Fact]
        public void CanGenerate()
        {
            var key = BiPrivateKey.Generate("Test2");

            var output = File.OpenWrite(@"Resources\Test2.biprivatekey");
            using var writer = new BinaryWriterEx(output);
            key.Write(writer);
        }

        [Fact]
        public void CanExportParameters()
        {
            var input = File.OpenRead(@"Resources\Test.biprivatekey");
            using var reader = new BinaryReaderEx(input);
            var key = BiPrivateKey.Read(reader);
            var parameters = key.ToRSAParameters();
            
            using var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
        }
    }
}
