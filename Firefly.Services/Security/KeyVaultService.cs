using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using Firefly.Core.Configurations;
using Firefly.Core.Http;
using Firefly.Core.Services.Security;
using Firefly.Utilities.Extensions;
using Microsoft.Extensions.Logging;

namespace Firefly.Services.Security
{
    /// <summary>
    /// Represents an implementation of an <see cref="IKeyVaultService"/>.
    /// </summary>
    public class KeyVaultService : IKeyVaultService
    {
        private readonly IFireflyHttpClientFactory _httpClientFactory;
        private readonly IFireflyConfiguration _configuration;

        private readonly SecretClient _secretClient;

        private readonly Dictionary<string, KeyVaultSecret> _retrievedSecrets = new Dictionary<string, KeyVaultSecret>();
        private readonly Dictionary<string, KeyVaultKey> _retrievedKeys = new Dictionary<string, KeyVaultKey>();

        private readonly ILogger<KeyVaultService> _logger;

        /// <summary>
        /// Creates an instance of a <see cref="KeyVaultService"/>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="configuration"/> is null.</exception>
        public KeyVaultService(IFireflyConfiguration configuration, IFireflyHttpClientFactory clientFactory, ILoggerFactory? loggerFactory)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            loggerFactory ??= new LoggerFactory();

            _logger = loggerFactory.CreateLogger<KeyVaultService>();

            _secretClient = new SecretClient(_configuration.KeyVaultUri, _configuration.KeyVaultCredential, new SecretClientOptions()
            {
                Retry =
                {
                    Delay = TimeSpan.FromSeconds(1),
                    MaxDelay = TimeSpan.FromSeconds(1),
                    MaxRetries = 1,
                    Mode = RetryMode.Exponential
                }
            });

            _httpClientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        }

        /// <inheritdoc />
        public KeyVaultSecret GetSecret(string secretKey, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                if (_retrievedSecrets.ContainsKey(secretKey)) return _retrievedSecrets[secretKey];

                var response = _secretClient.GetSecret(secretKey, cancellationToken: cancellationToken)
                    ?? throw new ApplicationException($"Unable to retrieve secret: {secretKey}");
                _retrievedSecrets.Add(secretKey, response.Value);

                return response.Value;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no secret name is provided</exception>
        /// <exception cref="ApplicationException">Thrown when no secret is retrieved</exception>
        /// <exception cref="FileNotFoundException">Thrown when a secret isn't found for provided <paramref name="secretKey"/></exception>
        public async Task<KeyVaultSecret> GetSecretAsync(string secretKey, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                if ( _retrievedSecrets.ContainsKey(secretKey) ) return _retrievedSecrets[secretKey];

                var response = await _secretClient.GetSecretAsync(secretKey, cancellationToken: cancellationToken).ConfigureAwait(false)
                    ?? throw new ApplicationException($"Unable to retrieve secret: {secretKey}");
                _retrievedSecrets.Add(secretKey, response.Value);

                return response.Value;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public KeyVaultKey GetKey(string keyName, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                if ( TryGetKey(keyName, out var value) )
                {
                    return value;
                }

                var client = _httpClientFactory.CreateClient(nameof(KeyVaultService));
                client.BaseAddress = _configuration.KeyVaultUri;
                using var responseMessage = client.GetAsync($"keys/{keyName}", cancellationToken).Result;
                responseMessage.EnsureSuccessStatusCode();

                var body = responseMessage.Content.ReadAsStringAsync().Result;
                var key = JsonSerializer.Deserialize<KeyVaultKey>(body, new JsonSerializerOptions());

                _retrievedKeys.TryAdd(keyName, key);

                return key;
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        public async Task<KeyVaultKey> GetKeyAsync(string keyName, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                if (TryGetKey(keyName, out var value))
                {
                    return value;
                }

                var client = _httpClientFactory.CreateClient(nameof(KeyVaultService));
                client.BaseAddress = _configuration.KeyVaultUri;
                using var responseMessage = await client.GetAsync($"keys/{keyName}", cancellationToken);
                responseMessage.EnsureSuccessStatusCode();

                var stream = await responseMessage.Content.ReadAsStreamAsync();
                var key = await JsonSerializer.DeserializeAsync<KeyVaultKey>(stream, new JsonSerializerOptions(), cancellationToken);

                _retrievedKeys.TryAdd(keyName, key);

                return key;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        private bool TryGetKey(string keyName, out KeyVaultKey key)
        {
            keyName = !keyName.IsNullOrWhitespace() ? keyName : throw new ArgumentNullException(nameof(keyName));
            key = _retrievedKeys.TryGetValue(keyName, out var retrievedKey) ? retrievedKey : new KeyVaultKey(keyName);
            return _retrievedKeys.ContainsKey(keyName);
        }
    }
}
