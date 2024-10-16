using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;

using Firefly.Core.Configurations;
using Firefly.Core.Services.Security;
using Firefly.Utilities.Extensions;

using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Logging;

namespace Firefly.Services.Security
{
    /// <summary>
    /// Represents an implementation of an <see cref="IKeyVaultService"/>.
    /// </summary>
    public class KeyVaultService : IKeyVaultService
    {
        private readonly SecretClient _secretClient;
        private readonly KeyClient _keyClient;

        private readonly Dictionary<string, KeyVaultSecret> _retrievedSecrets = new Dictionary<string, KeyVaultSecret>();
        private readonly Dictionary<string, KeyVaultKey> _retrievedKeys = new Dictionary<string, KeyVaultKey>();

        private readonly ILogger<KeyVaultService> _logger;

        /// <summary>
        /// Creates an instance of a <see cref="KeyVaultService"/>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="configuration"/> is null.</exception>
        public KeyVaultService(IFireflyConfiguration configuration, SecretClient? secretClient, KeyClient? keyClient,
            ILoggerFactory? loggerFactory)
        {
            loggerFactory ??= new LoggerFactory();

            _logger = loggerFactory.CreateLogger<KeyVaultService>();

            try
            {
                configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

                _secretClient = secretClient ?? new SecretClient(configuration.KeyVaultUri, configuration.KeyVaultCredential, new SecretClientOptions()
                {
                    Retry =
                    {
                        Delay = TimeSpan.FromSeconds(1),
                        MaxDelay = TimeSpan.FromSeconds(1),
                        MaxRetries = 1,
                        Mode = RetryMode.Exponential
                    }
                });

                _keyClient = keyClient ?? new KeyClient(configuration.KeyVaultUri, new DefaultAzureCredential(),
                    new KeyClientOptions(
                        Enum.TryParse<KeyClientOptions.ServiceVersion>(
                        configuration["KeyVaultClientApiVersion"] ?? "V7_5",
                        out var result)
                        ? result
                        : KeyClientOptions.ServiceVersion.V7_5));
            } catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no secret name is provided</exception>
        /// <exception cref="ApplicationException">Thrown when no secret is retrieved</exception>
        /// <exception cref="FileNotFoundException">Thrown when a secret isn't found for provided <paramref name="secretKey"/></exception>
        public KeyVaultSecret GetSecret(string secretKey, string? version, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(KeyVaultService)} {nameof(GetSecret)} secretKey={secretKey} version={version}");

            try
            {
                if ( secretKey.IsNullOrWhitespace() ) throw new ArgumentNullException(nameof(secretKey));

                if ( _retrievedSecrets.TryGetValue(secretKey, out var secret) ) return secret;

                var response = _secretClient.GetSecret(secretKey, cancellationToken: cancellationToken)
                    ?? throw new ApplicationException($"Failed to retrieve secret: '{secretKey}'");

                if ( !response.HasValue )
                {
                    var raw = response.GetRawResponse();
                    throw new FileNotFoundException(
                            $"Failed to retrieve secret: '{secretKey}'. Code={raw.Status} Reason={raw.ReasonPhrase}");
                }

                _retrievedSecrets.Add(secretKey, response.Value);

                return response.Value;
            } catch ( Exception ex )
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no secret name is provided</exception>
        /// <exception cref="ApplicationException">Thrown when no secret is retrieved</exception>
        /// <exception cref="FileNotFoundException">Thrown when a secret isn't found for provided <paramref name="secretKey"/></exception>
        public async Task<KeyVaultSecret> GetSecretAsync(string secretKey, string? version, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(KeyVaultService)} {nameof(GetSecretAsync)} secretKey={secretKey} version={version}");

            try
            {
                if ( secretKey.IsNullOrWhitespace() ) throw new ArgumentNullException(nameof(secretKey));

                if ( _retrievedSecrets.TryGetValue(secretKey, out var secret) ) return secret;

                var response = await _secretClient.GetSecretAsync(secretKey, cancellationToken: cancellationToken)
                               ?? throw new ApplicationException($"Failed to retrieve secret: '{secretKey}'");

                if ( !response.HasValue )
                {
                    var raw = response.GetRawResponse();
                    throw new FileNotFoundException(
                        $"Failed to retrieve secret: '{secretKey}'. Code={raw.Status} Reason={raw.ReasonPhrase}");
                }

                _retrievedSecrets.Add(secretKey, response.Value);

                return response.Value;
            } catch ( Exception ex )
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no key name is provided</exception>
        /// <exception cref="KeyVaultErrorException">Thrown when a secret isn't found for provided <paramref name="keyName"/></exception>
        public KeyVaultKey GetKey(string keyName, string? version,
            CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(KeyVaultService)} {nameof(GetKey)} keyName={keyName} version={version}");

            try
            {
                if ( keyName.IsNullOrWhitespace() ) throw new ArgumentNullException(nameof(keyName));

                if ( TryGetKey(keyName, out var value) )
                {
                    return value;
                }

                var response = _keyClient.GetKey(keyName, version, cancellationToken);

                if ( !response.HasValue )
                {
                    throw new KeyVaultErrorException("An unknown error occurred attempting to retrieve key");
                }

                _retrievedKeys.TryAdd(keyName, response.Value);

                return response.Value;
            } catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no key name is provided</exception>
        /// <exception cref="KeyVaultErrorException">Thrown when a secret isn't found for provided <paramref name="keyName"/></exception>
        public async Task<KeyVaultKey> GetKeyAsync(string keyName, string? version, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(KeyVaultService)} {nameof(GetKeyAsync)} keyName={keyName} version={version}");

            try
            {
                if ( keyName.IsNullOrWhitespace() ) throw new ArgumentNullException(nameof(keyName));

                if ( TryGetKey(keyName, out var value) )
                {
                    return value;
                }

                var response = await _keyClient.GetKeyAsync(keyName, version, cancellationToken);

                if ( !response.HasValue )
                {
                    throw new KeyVaultErrorException("An unknown error occurred attempting to retrieve key");
                }

                _retrievedKeys.TryAdd(keyName, response.Value);

                return _retrievedKeys.GetValueOrDefault(keyName);
            } catch ( Exception ex )
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
