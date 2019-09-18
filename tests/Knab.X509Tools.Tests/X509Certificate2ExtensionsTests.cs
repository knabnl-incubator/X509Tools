using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace Knab.X509Tools.Tests
{
    public class X509Certificate2ExtensionsTests
    {
        [Theory]
        [InlineData("Content\\client.pem", false)]
        [InlineData("Content\\ca_int.pem", false)]
        [InlineData("Content\\ca_root.pem", true)]
        public async Task Should_check_if_certificate_is_root(string certPath, bool isRoot)
        {
            var pem = await File.ReadAllBytesAsync(certPath);
            var cert = new X509Certificate2(pem);
            Assert.Equal(isRoot, cert.IsRoot());
        }
    }
}