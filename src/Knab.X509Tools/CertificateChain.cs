using System;
using System.Collections.Generic;
using System.Linq;

namespace Knab.X509Tools
{
    public class CertificateChain
    {
        public IReadOnlyList<CertificateChainItem> Certificates => _certificates;
        public CertificateChainStatus Status { get; internal set; } = CertificateChainStatus.OK;
        public Exception Error { get; internal set; }

        private readonly List<CertificateChainItem> _certificates = new List<CertificateChainItem>();
        internal void Add(CertificateChainItem item) => _certificates.Add(item);

        public string ToPem()
        {
            return String.Join(Environment.NewLine, _certificates.Select(x => x.CertificateAsPem));
        }
    }
}