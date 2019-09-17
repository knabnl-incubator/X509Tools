using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Knab.X509Tools
{
    public class X509ChainComposer
    {
        private readonly HttpClient _httpClient;

        public X509ChainComposer(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<string> ComposeChain(string pem)
        {
            var sb = new StringBuilder();
            var x509 = new X509Certificate2(Encoding.ASCII.GetBytes(pem));
            await ComposeChain(x509, sb);
            return sb.ToString();
        }

        private async Task ComposeChain(X509Certificate2 certificate, StringBuilder sb)
        {
            sb.AppendLine(certificate.ToPEM());
            if (certificate.IsRoot())
            {
                return;
            }
            var uri = certificate.GetSignerCertificateUri();
            var file = await DownloadCertificate(uri, certificate);
            var signer = new X509Certificate2(file);
            await ComposeChain(signer, sb);
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