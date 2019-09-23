using System;

namespace Knab.X509Tools
{
    public class CertificateChainBuilder
    {
        private CertificateChain _certificateChain;
        
        public CertificateChainBuilder()
        {
            _certificateChain = new CertificateChain();
        }

        public void AddItem(string certificateAsPem, string url)
        {
            _certificateChain.Add(new CertificateChainItem(certificateAsPem, url));
        }

        public void SetError(CertificateChainStatus status, Exception ex)
        {
            _certificateChain.Status = status;
            _certificateChain.Error = ex;
        }

        public CertificateChain Build()
        {
            return _certificateChain;
        }
    }
}