// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName={functionname}

using Azure.Messaging;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Firefly.Alerts
{
    public class KeyVaultChanges(ILogger<KeyVaultChanges> logger)
    {
        [Function(nameof(KeyVaultChanges))]
        public void Run([EventGridTrigger] CloudEvent cloudEvent)
        {
            logger.LogInformation("Event type: {type}, Event subject: {subject}", cloudEvent.Type, cloudEvent.Subject);
        }
    }
}
