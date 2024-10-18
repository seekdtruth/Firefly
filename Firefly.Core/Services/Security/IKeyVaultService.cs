using System.Threading;
using System.Threading.Tasks;

using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;

namespace Firefly.Core.Services.Security
{
    /// <summary>
    /// Represents an <see cref="IKeyVaultService"/>
    /// </summary>
    public interface IKeyVaultService
    {
        /// <summary>
        /// Retrieves a <see cref="KeyVaultSecret"/>
        /// </summary>
        /// <param name="secretKey">Name of the <see cref="KeyVaultSecret"/></param>
        /// <param name="version">Version of the requested <see cref="KeyVaultSecret"/></param>
        /// <returns>Requested <see cref="KeyVaultSecret"/></returns>
        KeyVaultSecret GetSecret(string secretKey, string? version, CancellationToken cancellationToken = new CancellationToken());

        /// <inheritdoc cref="GetSecret"/>
        Task<KeyVaultSecret> GetSecretAsync(string secretKey, string? version, CancellationToken cancellationToken = new CancellationToken());

        /// <summary>
        /// Retrieves a <see cref="KeyVaultKey"/>
        /// </summary>
        /// <param name="keyName">Name of the <see cref="KeyVaultKey"/></param>
        /// <param name="version">Version of requested <see cref="KeyVaultKey"/></param>
        /// <param name="cancellationToken"></param>
        /// <returns>Requested <see cref="KeyVaultKey"/></returns>
        KeyVaultKey GetKey(string keyName, string? version,
            CancellationToken cancellationToken = new CancellationToken());

        /// <inheritdoc cref="GetKey"/>
        Task<KeyVaultKey> GetKeyAsync(string keyName, string? version, CancellationToken cancellationToken = new CancellationToken());
    }
}
