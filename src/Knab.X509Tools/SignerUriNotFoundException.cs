using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;

namespace Knab.X509Tools
{
    [Serializable]
    public class SignerUriNotFoundException : Exception
    {
        public X509Certificate2 Certificate { get; set; }

        public SignerUriNotFoundException(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }

        public SignerUriNotFoundException(string message) : base(message)
        {
        }

        public SignerUriNotFoundException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected SignerUriNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}