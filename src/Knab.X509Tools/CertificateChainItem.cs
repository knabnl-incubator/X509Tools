namespace Knab.X509Tools
{
    public class CertificateChainItem
    {
        public string CertificateAsPem { get; set; }
        public string Url { get; set; }
        public CertificateChainItem(string certificateAsPem, string url)
        {
            CertificateAsPem = certificateAsPem;
            Url = url;
        }
    }
}