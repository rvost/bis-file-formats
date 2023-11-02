using BIS.Core.Streams;

namespace BIS.Signatures.Test
{
    public class SigningTests
    {
        private readonly PBO.PBO pbo;
        private readonly BiPrivateKey key;
        private readonly BiSign v3;
        private readonly BiSign v2;

        public SigningTests()
        {
            pbo = new PBO.PBO(@"Resources\Test_Tank_01.pbo");
            var keyStream = File.OpenRead(@"Resources\Test.biprivatekey");
            using var keyReader = new BinaryReaderEx(keyStream);
            key = BiPrivateKey.Read(keyReader);

            var v3Stream = File.OpenRead(@"Resources\Test_Tank_01.pbo.Test.bisign");
            using var v3Reader = new BinaryReaderEx(v3Stream);
            v3 = BiSign.Read(v3Reader);

            var v2Stream = File.OpenRead(@"Resources\Test_Tank_01.pbo.Test.V2.bisign");
            using var v2Reader = new BinaryReaderEx(v2Stream);
            v2 = BiSign.Read(v2Reader);
        }

        [Fact]
        public void CanSignV3()
        {
            var signature = Signing.Sign(key, BiSignVersion.V3, pbo);

            Assert.Equal(v3.Name, signature.Name);
            Assert.Equal(v3.Sig1, signature.Sig1);
            Assert.Equal(v3.Sig2, signature.Sig2);
            Assert.Equal(v3.Sig3, signature.Sig3);
        }

        [Fact]
        public void CanSignV2()
        {
            var signature = Signing.Sign(key, BiSignVersion.V2, pbo);

            Assert.Equal(v2.Name, signature.Name);
            Assert.Equal(v2.Sig1, signature.Sig1);
            Assert.Equal(v2.Sig2, signature.Sig2);
            Assert.Equal(v2.Sig3, signature.Sig3);
        }

        [Fact]
        public void CanVerifyV3()
        {
            var pubKey = v3.PublicKey;
            var res = Signing.Verify(pubKey, v3, pbo);

            Assert.True(res);
        }

        [Fact]
        public void CanVerifyV2()
        {
            var pubKey = v2.PublicKey;
            var res = Signing.Verify(pubKey, v2, pbo);

            Assert.True(res);
        }

        [Fact]
        public void CanVerifyWithAllowedKeys()
        {
            var allowedKeysHaveKey = new HashSet<BiPublicKey>(new[] { v3.PublicKey, BiPrivateKey.Generate("Foo").ToPublicKey() });
            var allowedKeysNoKey = new HashSet<BiPublicKey>(new[] { BiPrivateKey.Generate("Foo").ToPublicKey() });
            
            var haveKeyResult = Signing.Verify(allowedKeysHaveKey, v3, pbo);
            var noKeyResult = Signing.Verify(allowedKeysNoKey, v3, pbo);

            Assert.True(haveKeyResult);
            Assert.False(noKeyResult);
        }
    }
}
