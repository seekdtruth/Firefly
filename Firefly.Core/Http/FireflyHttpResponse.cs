using System.Net;

namespace Firefly.Core.Http
{
    /// <summary>
    /// Represents an abstract class for HTTP Responses
    /// </summary>
    public abstract class FireflyHttpResponse
    {
        protected FireflyHttpResponse(HttpStatusCode statusCode, string statusMessage)
        {
            this.StatusCode = statusCode;
            this.StatusMessage = statusMessage;
        }

        /// <summary>
        /// The <see cref="HttpStatusCode"/> of the response
        /// </summary>
        public HttpStatusCode StatusCode { get; set; }

        /// <summary>
        /// The reason phrase or exception message, if applicable
        /// </summary>
        public string StatusMessage { get; set; }
    }
}
