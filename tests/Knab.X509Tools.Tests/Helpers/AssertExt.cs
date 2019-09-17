using Xunit;

namespace Knab.X509Tools.Tests.Helpers
{
    public static class AssertExt
    {
        public static void Equal(string expected, string certificateBase64)
        {
            Assert.Equal(FormatForComparison(expected), FormatForComparison(certificateBase64));
        }

        private static string FormatForComparison(string cert) =>
            cert.Replace("\n", "").Replace("\r", "");
    }
}