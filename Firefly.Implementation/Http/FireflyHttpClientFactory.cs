using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Firefly.Core.Http;

namespace Firefly.Implementation.Http
{
    /// <summary>
    /// Implementation of an <see cref="IFireflyHttpClientFactory"/> interface
    /// </summary>
    public class FireflyHttpClientFactory : IFireflyHttpClientFactory
    {
        private readonly IHttpMessageHandlerFactory _httpMessageHandlerFactory;

        /// <summary>
        /// Creates an instance of a <see cref="FireflyHttpClientFactory"/>
        /// </summary>
        /// <param name="handlerFactory"></param>
        public FireflyHttpClientFactory(IHttpMessageHandlerFactory handlerFactory)
        {
            _httpMessageHandlerFactory = handlerFactory;
        }

        /// <inheritdoc />
        public HttpClient CreateClient(string name)
        {
            return new HttpClient((HttpClientHandler) _httpMessageHandlerFactory.CreateHandler());
        }

        /// <inheritdoc />
        public HttpClient CreateClient(HttpMessageHandler handler)
        {
            return new HttpClient(handler);
        }

        /// <inheritdoc />
        public HttpClient CreateClient(X509Certificate2 certificate)
        {
            var handler = (HttpClientHandler)_httpMessageHandlerFactory.CreateHandler();
            handler.ClientCertificates.Add(certificate);
            return CreateClient(handler);
        }

        /// <inheritdoc />
        public HttpMessageHandler CreateHandler()
        {
            return _httpMessageHandlerFactory.CreateHandler();
        }

        /// <inheritdoc />
        public HttpClientHandler CreateHandler(X509Certificate2 certificate)
        {
            var handler = (HttpClientHandler) _httpMessageHandlerFactory.CreateHandler();
            handler.ClientCertificates.Add(certificate);
            return handler;
        }
    }
}
