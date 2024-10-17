using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Firefly.Core.Http
{
    /// <summary>
    /// Interface for an <see cref="IFireflyHttpClientFactory"/>
    /// </summary>
    public interface IFireflyHttpClientFactory : IHttpClientFactory
    {
        /// <summary>
        /// Create an <see cref="HttpClient"/> with given <see cref="X509Certificate2"/>
        /// </summary>
        /// <param name="certificate">Certificate to add to request headers</param>
        /// <returns><see cref="HttpClient"/></returns>
        HttpClient CreateClient(X509Certificate2 certificate);

        /// <summary>
        /// Create an <see cref="HttpClient"/> with given handler
        /// </summary>
        /// <param name="handler">Handler to use to create the client</param>
        /// <returns><see cref="HttpClient"/></returns>
        HttpClient CreateClient(HttpMessageHandler handler);

        /// <summary>
        /// Create a <see cref="HttpMessageHandler"/>
        /// </summary>
        /// <returns>An <see cref="HttpMessageHandler"/></returns>
        HttpMessageHandler CreateHandler();

        /// <summary>
        /// Create an <see cref="HttpClientHandler"/> with certificate loaded
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns>An <see cref="HttpClientHandler"/> with certificate</returns>
        HttpClientHandler CreateHandler(X509Certificate2 certificate);
    }
}
