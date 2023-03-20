namespace BIS.Signatures.Test
{
    public class PboExtensionsTests
    {
        [Fact]
        public void CanReadChecksum()
        {
            var pbo = new PBO.PBO(@"Resources\test.pbo");
            var expected = new byte[20] { 0x8, 0x64, 0x1A, 0x93, 0x4B, 0x26, 0xFE, 0xC6, 0x8E, 0x30, 0x7D, 0x3A, 0xBC, 0xBC, 0xC3, 0xC5, 0x35, 0xB7, 0xAB, 0x35 };

            var actual = pbo.ReadChecksum();

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CanCalculateChecksum()
        {
            var pbo = new PBO.PBO(@"Resources\test.pbo");
            var expected = new byte[20] { 0x8, 0x64, 0x1A, 0x93, 0x4B, 0x26, 0xFE, 0xC6, 0x8E, 0x30, 0x7D, 0x3A, 0xBC, 0xBC, 0xC3, 0xC5, 0x35, 0xB7, 0xAB, 0x35 };

            var actual = pbo.CalculateChecksum();

            Assert.Equal(expected, actual);
        }
    }
}