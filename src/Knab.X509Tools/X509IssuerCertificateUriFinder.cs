using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Knab.X509Tools
{
    public class X509IssuerCertificateUriFinder
    {
        private const string AuthorityInformationAccessOid = "1.3.6.1.5.5.7.1.1";

        private readonly List<Func<string, string>> _findActions = new List<Func<string, string>>();

        public X509IssuerCertificateUriFinder()
        {
            _findActions.Add(x => Regex.Match(x, "https?://.+((.+crt)|(.+cer))").Value);
            _findActions.Add(x => Regex.Match(x, "https?://.+").Value);
        }

        public void AddCustomFilter(Func<string, string> findAction)
        {
            _findActions.Add(findAction);
        }

        public void ClearFilters()
        {
            _findActions.Clear();
        }

        public Uri Find(X509Certificate2 certificate)
        {
            var data = FindAuthorityInformationExtension(certificate);
            string url = null;
            foreach(var filter in _findActions)
            {
                url = filter(data);
                if (!string.IsNullOrEmpty(url))
                {
                    break;
                }
            }
            
            if(string.IsNullOrEmpty(url))
            {
                throw new SignerUriNotFoundException(certificate);
            }
            return new Uri(url);
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
    }
}
