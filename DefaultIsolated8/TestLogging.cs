using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace DefaultIsolated8
{
    public class TestLogging
    {
        private readonly ILogger<TestLogging> _logger;

        public TestLogging(ILogger<TestLogging> logger)
        {
            _logger = logger;
        }

        [Function("TestLogging")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequest req)
        {
            _logger.LogDebug("Logging Debug");
            _logger.LogMetric("Logging metric", 100);
            _logger.LogInformation("Logging information");
            _logger.LogWarning("Logging warning");
            _logger.LogError("Logging error");
            _logger.LogCritical("Logging critical");
            return new OkObjectResult("Welcome to Azure Functions!");
        }
    }
}
