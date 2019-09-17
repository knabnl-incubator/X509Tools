using System;
using System.Security.Cryptography.X509Certificates;

namespace Knab.X509Tools
{
    [Serializable]
    public class SignerDownloadException : Exception
    {
        
        public SignerDownloadException(Uri uri, X509Certificate2 certificate, Exception innerException) : base("Could not download signer certificate", innerException)
        {
            Uri = uri;
            Certificate = certificate;
        }
        
        public Uri Uri { get; }
        public X509Certificate2 Certificate { get; }
    }
}