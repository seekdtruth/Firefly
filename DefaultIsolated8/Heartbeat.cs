using System;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace DefaultIsolated8
{
    public class Heartbeat
    {
        private readonly ILogger _logger;

        public Heartbeat(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<Heartbeat>();
        }

        [Function("Heartbeat")]
        public void Run([TimerTrigger("0 */1 * * * *")] TimerInfo myTimer)
        {
            _logger.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");
            
            if (myTimer.ScheduleStatus is not null)
            {
                _logger.LogInformation($"Next timer schedule at: {myTimer.ScheduleStatus.Next}");
            }
        }
    }
}
