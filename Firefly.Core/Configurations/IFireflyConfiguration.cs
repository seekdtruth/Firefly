using System;

using Microsoft.Extensions.Configuration;
using Microsoft.WindowsAzure.Storage;

namespace Firefly.Core.Configurations
{
    /// <summary>
    /// Represents an <see cref="IFireflyConfiguration"/>.
    /// </summary>
    public interface IFireflyConfiguration : IConfiguration
    {
        /// <summary>
        /// Gets a string configuration value
        /// </summary>
        string? GetValue(string key);

        /// <summary>
        /// Gets an int configuration value
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if the configuration value isn't found.</exception>
        /// <exception cref="FormatException" />
        /// <exception cref="OverflowException" />
        int? GetIntValue(string key);

        /// <summary>
        /// Gets a string configuration value
        /// </summary>
        /// <exception>Throws an <see cref="ArgumentNullException"/> if the configuration value isn't found.</exception>
        string GetRequiredValue(string key);

        /// <summary>
        /// Gets a byte[] configuration value
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if the configuration value isn't found.</exception>
        byte[] GetRequiredBytes(string key);

        /// <summary>
        /// The current <see cref="Environment"/>
        /// </summary>
        Environment Environment { get; }
    }
}