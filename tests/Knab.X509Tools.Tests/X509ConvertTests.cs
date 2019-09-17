using Knab.X509Tools.Tests.Helpers;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Knab.X509Tools.Tests
{
    public class X509ConvertTests
    {

        [Fact]
        public async Task Should_convert_der_to_pem()
        {
            var der = await File.ReadAllBytesAsync("Content\\ca_root.crt");
            var expected = await File.ReadAllTextAsync("Content\\ca_root.pem");

            var pem = X509Convert.ConvertToPem(der);
            
            AssertExt.Equal(expected, pem);
        }
    }
}