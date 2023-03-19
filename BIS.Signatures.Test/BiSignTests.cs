using BIS.Core.Streams;

namespace BIS.Signatures.Test
{
    public class BiSignTests
    {
        [Theory]
        [InlineData(@"Resources\test.pbo.Test.bisign", BiSignVersion.V3)]
        [InlineData(@"Resources\test.pbo.Test.V2.bisign", BiSignVersion.V2)]
        public void CanRead(string file, BiSignVersion expectedVersion)
        {
            var input = File.OpenRead(file);
            var reader = new BinaryReaderEx(input);

            var sign = BiSign.Read(reader);

            Assert.NotNull(sign);
            Assert.Equal("Test", sign.Name);
            Assert.Equal(expectedVersion, sign.Version);
        }

        [Theory]
        [InlineData(@"Resources\test.pbo.Test.bisign")]
        [InlineData(@"Resources\test.pbo.Test.V2.bisign")]
        public void CanWrite(string file)
        {
            var input = File.OpenRead(file);
            var expected = new MemoryStream();
            input.CopyTo(expected);
            input.Position = 0;
            var reader = new BinaryReaderEx(input);
            var sign = BiSign.Read(reader);

            var output = new MemoryStream();
            var writer = new BinaryWriterEx(output);
            sign.Write(writer);

            TestsHelpers.AssertStreamsEqual(expected, output);
        }
    }
}
