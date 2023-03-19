internal static class TestsHelpers
{
    public static void AssertStreamsEqual(MemoryStream expected, MemoryStream actual)
    {
        Assert.Equal(expected.Length, actual.Length);

        expected.Position = 0;
        actual.Position = 0;

        var expectedArray = expected.ToArray();
        var actualArray = actual.ToArray();

        Assert.Equal<IEnumerable<byte>>(expectedArray, actualArray);
    }
}