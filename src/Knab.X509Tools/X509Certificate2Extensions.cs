using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Knab.X509Tools
{
    public static class X509Certificate2Extensions
    {
        private const string AuthorityInformationAccessOid = "1.3.6.1.5.5.7.1.1";

        public static Uri GetSignerCertificateUri(this X509Certificate2 certificate)
        {
            var data = FindAuthorityInformationExtension(certificate);
            var findUri = new Regex(".+ur[li][\\=:]((.+crt)|(.+cer))", RegexOptions.IgnoreCase);
            var result = findUri.Match(data);
            if (result.Groups.Count < 2)
            {
                throw new SignerUriNotFoundException(certificate);
            }
            var value = result.Groups[1].Captures[0].Value;
            return new Uri(value);
        }

        private static string FindAuthorityInformationExtension(X509Certificate2 certificate)
        {
            string data = null;
            foreach (var ext in certificate.Extensions)
            {
                if (ext.Oid.Value == AuthorityInformationAccessOid)
                {
                    var asndata = new AsnEncodedData(ext.Oid, ext.RawData);
                    data = asndata.Format(true);
                    break;
                }
            }
            return data ?? throw new SignerUriNotFoundException(certificate);
        }

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
