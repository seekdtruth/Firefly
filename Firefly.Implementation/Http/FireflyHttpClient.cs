using System;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Firefly.Core.Configurations;
using Firefly.Core.Http;
using Firefly.Utilities.Extensions;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

using Environment = Firefly.Core.Configurations.Environment;

namespace Firefly.Implementation.Http
{
    /// <summary>
    /// Represents an abstract <see cref="IFireflyHttpClient"/> implementation
    /// </summary>
    public abstract class FireflyHttpClient : IFireflyHttpClient
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<FireflyHttpClient> _logger;
        private readonly string _baseUrl;

        protected FireflyHttpClient(IFireflyHttpClientFactory clientFactory, IFireflyConfiguration configuration,
            ILoggerFactory? loggerFactory)
            : this(clientFactory, configuration, loggerFactory, configuration.GetValue("ServiceUrl"))
        {
        }

        protected FireflyHttpClient(IFireflyHttpClientFactory clientFactory, IFireflyConfiguration configuration, ILoggerFactory? loggerFactory, string? baseUrl)
        {
            _httpClient = clientFactory.CreateClient();
            _logger = loggerFactory is null ? new LoggerFactory().CreateLogger<FireflyHttpClient>() : loggerFactory.CreateLogger<FireflyHttpClient>();

            if (!baseUrl.IsNullOrWhitespace() && Regex.IsMatch(baseUrl,
                         @"http://[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)") )
            {
                _baseUrl = baseUrl;
            }
            else
            {
                _baseUrl = configuration.Environment == Environment.Local
                    ? "https://localhost/"
                    : configuration["ServiceAddress"] ?? string.Empty;

                if (!baseUrl.IsNullOrWhitespace())
                    _baseUrl +=  !baseUrl.StartsWith("/") ? "/" + baseUrl : baseUrl;
            }
        }

        /// <inheritdoc />
        public async Task<TResponse> GetAsync<TResponse>(string path, CancellationToken token = new CancellationToken())
            where TResponse : FireflyHttpResponse, new()
        {
            return await SendRequest<TResponse>(HttpMethod.Get, path, default(IFireflyHttpRequest), token);
        }

        /// <inheritdoc />
        public async Task<TResponse> PostAsync<TRequest, TResponse>(TRequest request, string path, CancellationToken token = new CancellationToken())
            where TRequest : IFireflyHttpRequest, new()
            where TResponse : FireflyHttpResponse, new()
        {
            return await SendRequest<TResponse>(HttpMethod.Post, path, request, token);
        }

        private async Task<TResponse> SendRequest<TResponse>(HttpMethod method, string path,
            IFireflyHttpRequest? request, CancellationToken token = new CancellationToken())
            where TResponse : FireflyHttpResponse, new()
        {
            using var requestMessage = new HttpRequestMessage(method, GetUrl(path));

            if ( request != null )
            {
                var content = JsonConvert.SerializeObject(requestMessage);
                requestMessage.Content = new StringContent(content);
            }

            using var responseMessage = await _httpClient.GetAsync(path, token);
            return await GetResponse<TResponse>(responseMessage);
        }

        private async Task<TResponse> GetResponse<TResponse>(HttpResponseMessage message) where TResponse : FireflyHttpResponse, new()
        {
            var response = new TResponse();

            try
            {
                LogResponse(message);

                message.EnsureSuccessStatusCode();

                var content = await message.Content.ReadAsStringAsync();

                if ( content.IsNullOrWhitespace() )
                {
                    response = JsonConvert.DeserializeObject<TResponse>(content) ?? response;
                }

                response.StatusCode = message.StatusCode;
                response.StatusMessage = message.ReasonPhrase;

                return response;
            } catch ( HttpRequestException requestException )
            {
                _logger.LogError(requestException, requestException.Message);
                response.StatusCode = HttpStatusCode.InternalServerError;
                response.StatusMessage = requestException.GetBaseException().Message;
                return response;
            } catch ( Exception e )
            {
                _logger.LogError(e, e.GetBaseException().Message);
                throw;
            }
        }

        private void LogResponse(HttpResponseMessage response)
        {
            _logger.LogInformation($"Response Received\tUri:{response.RequestMessage.RequestUri}\tStatusCode:{response.StatusCode}\tReasonPhrase:{response.ReasonPhrase}");
        }

        private string GetUrl(string path)
        {
            if ( Regex.IsMatch(path,
                    @"http://[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)") )
                return path;
            return _baseUrl + (path.StartsWith("/") ? path.Substring(1) : path);
        }
    }
}
