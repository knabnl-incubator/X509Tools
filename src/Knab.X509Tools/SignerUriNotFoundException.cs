using System;
using System.Runtime.Serialization;

namespace Knab.X509Tools
{
    [Serializable]
    public class SignerUriNotFoundException : Exception
    {
        public SignerUriNotFoundException()
        {
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