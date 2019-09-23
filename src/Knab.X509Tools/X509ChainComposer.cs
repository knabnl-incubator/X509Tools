using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Knab.X509Tools
{
    public partial class X509ChainComposer
    {
        private readonly HttpClient _httpClient;
        private readonly X509IssuerCertificateUriFinder _uriFinder;

        public X509ChainComposer(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _uriFinder = new X509IssuerCertificateUriFinder();
        }

        public async Task<CertificateChain> ComposeChain(string firstCertificateAsPem, string originalUrl = "http://localhost")
        {
            var builder = new CertificateChainBuilder();
            try
            {
                using (var x509 = new X509Certificate2(Encoding.ASCII.GetBytes(firstCertificateAsPem)))
                {
                    await ComposeChain(builder, x509, "http://localhost");
                }
            }
            catch(SignerUriNotFoundException sunfex)
            {
                builder.SetError(CertificateChainStatus.SignerUriNotFound, sunfex);
            }
            catch(SignerDownloadException sdex)
            {
                builder.SetError(CertificateChainStatus.ErrorDownloadingSigner, sdex);
            }
            return builder.Build();
        }

        private async Task ComposeChain(CertificateChainBuilder builder, X509Certificate2 x509, string url)
        {
            builder.AddItem(x509.ToPEM(), url);
            if (x509.IsRoot())
            {
                return;
            }
            
            var uri = _uriFinder.Find(x509);
            var file = await DownloadCertificate(uri, x509);
            
            using (var signer = new X509Certificate2(file))
            {
                await ComposeChain(builder, signer, uri.ToString());
            }
        }

        private async Task<byte[]> DownloadCertificate(Uri uri, X509Certificate2 certificate)
        {
            try
            {
                return await _httpClient.GetByteArrayAsync(uri);
            }
            catch (Exception ex)
            {
                throw new SignerDownloadException(uri, certificate, ex);
            }
        }
    }
}