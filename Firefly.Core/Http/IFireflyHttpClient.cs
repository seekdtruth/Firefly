using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Firefly.Core.Http
{
    /// <summary>
    /// Represents an interface for an <see cref="IFireflyHttpClient"/>
    /// </summary>
    public interface IFireflyHttpClient
    {
        /// <summary>
        /// Makes a <see cref="HttpMethod.Get"/> request
        /// </summary>
        /// <typeparam name="TResponse">The excepted response type</typeparam>
        /// <param name="path">The URL path for the request</param>
        /// <param name="token">The cancellation token, if applicable</param>
        /// <returns>A response of type <typeparam name="TResponse"></typeparam></returns>
        Task<TResponse> GetAsync<TResponse>(string path, CancellationToken token = default) where TResponse : FireflyHttpResponse, new();

        /// <summary>
        /// Makes a <see cref="HttpMethod.Post"/> request
        /// </summary>
        /// <typeparam name="TResponse">The excepted response type</typeparam>
        /// <param name="request">The outgoing request</param>
        /// <typeparam name="TRequest">The type of outgoing request</typeparam>
        /// <param name="path">The URL path for the request</param>
        /// <param name="token">The cancellation token, if applicable</param>
        /// <returns>A response of type <typeparam name="TResponse"></typeparam></returns>
        Task<TResponse> PostAsync<TRequest, TResponse>(TRequest request, string path,
            CancellationToken token = new CancellationToken())
            where TRequest : IFireflyHttpRequest, new()
            where TResponse : FireflyHttpResponse, new();
    }
}
