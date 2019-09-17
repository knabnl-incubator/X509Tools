using System;

namespace Knab.X509Tools
{
    public static class X509Convert
    {
        private const string BeginCertificate = "-----BEGIN CERTIFICATE-----";
        private const string EndCertificate = "-----END CERTIFICATE-----";

        public static string ConvertToPem(byte[] der) =>
            $"{BeginCertificate}\n{Convert.ToBase64String(der)}\n{EndCertificate}\n";
    }
}
