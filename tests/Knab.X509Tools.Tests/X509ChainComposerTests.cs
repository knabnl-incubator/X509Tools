using Knab.X509Tools.Tests.Helpers;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace Knab.X509Tools.Tests
{
    public class X509ChainComposerTests
    {

        [Fact]
        public async Task Should_build_the_certificate_chain_when_root()
        {
            var caRoot = await File.ReadAllTextAsync("Content\\ca_root.pem");
            var expected = caRoot;
            
            var client = new HttpClient();
            var x509 = new X509ChainComposer(client);
            var result = await x509.ComposeChain(caRoot);
            AssertExt.Equal(expected, result);
        }

        [Fact]
        public async Task Should_build_the_certificate_chain_when_intermediate()
        {
            var caInt = await File.ReadAllTextAsync("Content\\ca_int.pem");
            var caRoot = await File.ReadAllTextAsync("Content\\ca_root.pem");

            var expected = await File.ReadAllTextAsync("Content\\chain_int_root.pem");

            var handler = new HttpMessageHandlerStub();
            handler.AddRequestResponse("http://trust.quovadisglobal.com/qvrca2g3.crt", caRoot);

            var client = new HttpClient(handler);

            var x509 = new X509ChainComposer(client);
            var result = await x509.ComposeChain(caInt);

            AssertExt.Equal(expected, result);
        }

        [Fact]
        public async Task Should_build_the_certificate_chain()
        {
            var clientPem = await File.ReadAllTextAsync("Content\\client.pem");
            var caInt = await File.ReadAllTextAsync("Content\\ca_int.pem");
            var caRoot = await File.ReadAllTextAsync("Content\\ca_root.pem");

            var expected = await File.ReadAllTextAsync("Content\\chain_client_int_root.pem");

            var handler = new HttpMessageHandlerStub();
            handler.AddRequestResponse("http://trust.quovadisglobal.com/qventca2g3.crt", caInt);
            handler.AddRequestResponse("http://trust.quovadisglobal.com/qvrca2g3.crt", caRoot);

            var client = new HttpClient(handler);

            var x509 = new X509ChainComposer(client);
            var result = await x509.ComposeChain(clientPem);

            AssertExt.Equal(expected, result);
        }
    }
}