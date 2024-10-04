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
        /// <returns>Requested <see cref="KeyVaultSecret"/></returns>
        KeyVaultSecret GetSecret(string secretKey, CancellationToken cancellationToken = new CancellationToken());

        /// <inheritdoc cref="GetSecret"/>s
        Task<KeyVaultSecret> GetSecretAsync(string secretKey, CancellationToken cancellationToken = new CancellationToken());

        /// <summary>
        /// Retrieves a <see cref="KeyVaultKey"/>
        /// </summary>
        /// <param name="keyName">Name of the <see cref="KeyVaultKey"/></param>
        /// <returns>Requested <see cref="KeyVaultKey"/></returns>
        KeyVaultKey GetKey(string keyName, CancellationToken cancellationToken = new CancellationToken());

        /// <inheritdoc cref="GetKey"/>
        Task<KeyVaultKey> GetKeyAsync(string keyName, CancellationToken cancellationToken = new CancellationToken());
    }
}
