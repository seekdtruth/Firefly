using System;
using System.Collections.Generic;
using System.Threading;

using Azure.Identity;
using Firefly.Core.Configurations;
using Firefly.Utilities.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Newtonsoft.Json;

using Environment = Firefly.Core.Configurations.Environment;

namespace Firefly.Implementation.Configurations
{
    /// <summary>
    /// Represents an implementation of an <see cref="IFireflyConfiguration"/>
    /// </summary>
    public class FireflyConfiguration : IFireflyConfiguration
    {
        private const string ThumbprintKey = "KeyVault:Certificates:Thumbprint";

        private readonly IConfiguration _configuration;
        private readonly ILogger<FireflyConfiguration> _logger;

        /// <summary>
        /// Creates an instance of a <see cref="FireflyConfiguration"/>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="configuration"/> is null</exception>
        public FireflyConfiguration(IConfiguration configuration, ILoggerFactory? loggerFactory)
        {
            loggerFactory ??= new LoggerFactory();
            _logger = loggerFactory.CreateLogger<FireflyConfiguration>();

            try
            {
                _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
                Environment = EnvironmentExtensions.GetEnvironment();

                GetRequiredValue(ThumbprintKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc/>
        public string? this[string key]
        {
            get => GetValue(key);
            set => throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public Environment Environment { get; }

        /// <inheritdoc/>
        public int? GetIntValue(string key)
        {
            try
            {
                var value = GetValue(key) ?? string.Empty;

                if (value.IsNullOrWhitespace()) return null;

                return int.TryParse(value, out var result) ? (int?) result : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] GetRequiredBytes(string key)
        {
            return Convert.FromBase64String(GetRequiredValue(key));
        }

        /// <inheritdoc/>
        public string? GetValue(string key)
        {
            try
            {
                var value = _configuration[key];

                return value;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        public string GetRequiredValue(string key)
        {
            try
            {
                var value = GetValue(key);

                if (value.IsNullOrWhitespace())
                    throw new ArgumentNullException(key);

                return value;
            }
            catch (Exception e)
            {
                _logger.LogError(e, e.Message);
                throw;
            }
        }

        /// <inheritdoc/>
        public IEnumerable<IConfigurationSection> GetChildren()
        {
            return _configuration.GetChildren();
        }

        /// <inheritdoc/>
        public IChangeToken GetReloadToken()
        {
            return _configuration.GetReloadToken();
        }

        /// <inheritdoc/>
        public IConfigurationSection GetSection(string key)
        {
            return _configuration.GetSection(key);
        }
    }
}
