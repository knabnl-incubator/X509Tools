using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace Knab.X509Tools.Tests
{
    public class X509IssuerCertificateUriFinderTests
    {
        private X509IssuerCertificateUriFinder _finder;

        public X509IssuerCertificateUriFinderTests()
        {
            _finder = new X509IssuerCertificateUriFinder();
        }

        [Theory]
        [InlineData("Content\\client.pem", "http://trust.quovadisglobal.com/qventca2g3.crt")]
        [InlineData("Content\\ca_int.pem", "http://trust.quovadisglobal.com/qvrca2g3.crt")]
        [InlineData("Content\\client_with_signer_file_cer.pem", "https://cert.pkioverheid.nl/EVIntermediairCA.cer")]
        [InlineData("Content\\signer_v2.pem", "http://ocsp.telesec.de/ocspr")]
        [InlineData("Content\\signer_v3.pem", "http://www.cert.fnmt.es/certs/ACRAIZSERVIDORESSEGUROS.crt")]
        [InlineData("Content\\signer_v4.pem", "http://ocsp.izenpe.com")]
        [InlineData("Content\\signer_v5.pem", "http://autorite.certigna.fr/certigna.der")]
        public async Task Should_find_signer_uri(string certPath, string url)
        {
            var pem = await File.ReadAllBytesAsync(certPath);
            var expectedUri = new Uri(url);
            var cert = new X509Certificate2(pem);

            var uri = _finder.Find(cert);

            Assert.Equal(expectedUri, uri);
        }

        [Fact]
        public async Task Should_throw_when_signer_not_found()
        {
            var pem = await File.ReadAllBytesAsync("Content\\ca_root.pem");
            var cert = new X509Certificate2(pem);

            Assert.Throws<SignerUriNotFoundException>(() => _finder.Find(cert));
        }

        [Fact]
        public async Task Should_provide_details_in_the_exception()
        {
            var pem = await File.ReadAllBytesAsync("Content\\ca_root.pem");
            var cert = new X509Certificate2(pem);

            var ex = Assert.Throws<SignerUriNotFoundException>(() => _finder.Find(cert));
            Assert.Equal(ex.Certificate, cert);
        }
    }
}