using System;
using System.Net;

namespace Firefly.Core.Http
{
    /// <summary>
    /// Represents an abstract class for HTTP Responses
    /// </summary>
    public abstract class FireflyHttpResponse
    {
        /// <summary>
        /// The <see cref="HttpStatusCode"/> of the response
        /// </summary>
        public HttpStatusCode StatusCode { get; set; }

        /// <summary>
        /// The reason phrase or exception message, if applicable
        /// </summary>
        public string? StatusMessage { get; set; }
    }
}
