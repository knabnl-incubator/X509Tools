﻿using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace Knab.X509Tools.Tests
{
    public class X509Certificate2ExtensionsTests
    {

        [Theory]
        [InlineData("Content\\client.pem", "http://trust.quovadisglobal.com/qventca2g3.crt")]
        [InlineData("Content\\ca_int.pem", "http://trust.quovadisglobal.com/qvrca2g3.crt")]
        public async Task Should_find_signer_uri(string certPath, string url)
        {
            var pem = await File.ReadAllBytesAsync(certPath);
            var expectedUri = new Uri(url);
            var cert = new X509Certificate2(pem);
            Assert.Equal(expectedUri, cert.GetSignerCertificateUri());
        }

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

        [Fact]
        public async Task Should_throw_when_signer_not_found()
        {
            var pem = await File.ReadAllBytesAsync("Content\\ca_root.pem");
            var cert = new X509Certificate2(pem);

            Assert.Throws<SignerUriNotFoundException>(() => cert.GetSignerCertificateUri());
        }
    }
}