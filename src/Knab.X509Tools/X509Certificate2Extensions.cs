using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Knab.X509Tools
{
    public static class X509Certificate2Extensions
    {
        public static bool IsRoot(this X509Certificate2 certificate)
        {
            return certificate.Subject == certificate.Issuer;
        }

        public static string ToPEM(this X509Certificate2 certificate)
        {
            return X509Convert.ConvertToPem(certificate.RawData);
        }
    }
}
