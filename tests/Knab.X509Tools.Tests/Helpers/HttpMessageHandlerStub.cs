using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Knab.X509Tools.Tests.Helpers
{
    public class HttpMessageHandlerStub : HttpMessageHandler
    {
        private Dictionary<string, string> _responseMap { get; set; } = new Dictionary<string, string>();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(_responseMap[request.RequestUri.ToString()], Encoding.UTF8)
            });
        }

        public void AddRequestResponse(string url, string response)
        {
            _responseMap[url] = response;
        }
    }
}