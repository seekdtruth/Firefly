using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Firefly.Core.Services.Encryption
{
    /// <summary>
    /// Represents an interface for encryption services
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Encrypts an object
        /// </summary>
        /// <typeparam name="T">Type of object to encrypt</typeparam>
        /// <param name="obj">Object to be encrypted</param>
        /// <param name="certificate">Certificate to use for encryption</param>
        /// <returns>Encrypted object</returns>
        byte[] Encrypt<T>(T obj, X509Certificate2 certificate, CancellationToken token = new CancellationToken());

        /// <inheritdoc cref="Encrypt{T}"/>
        Task<byte[]> EncryptAsync<T>(T obj, X509Certificate2 certificate, CancellationToken token = new CancellationToken());

        /// <summary>
        /// Decrypts a stream
        /// </summary>
        /// <typeparam name="T">Type of object to be decrypted</typeparam>
        /// <param name="stream">Stream to decrypt</param>
        /// <param name="certificate">Certificate to use for decryption</param>
        /// <returns>Decrypted object</returns>
        T Decrypt<T>(Stream stream, X509Certificate2 certificate, CancellationToken token = new CancellationToken());

        /// <inheritdoc cref="Decrypt{T}(Stream,X509Certificate2,CancellationToken)"/>
        Task<T> DecryptAsync<T>(Stream stream, X509Certificate2 certificate, CancellationToken token = new CancellationToken());

        /// <summary>
        /// Decrypts a byte array
        /// </summary>
        /// <typeparam name="T">Type of object to be decrypted</typeparam>
        /// <param name="bytes">Byte array to decrypt</param>
        /// <param name="certificate">Certificate to use for decryption</param>
        /// <returns>Decrypted object</returns>
        T Decrypt<T>(byte[] bytes, X509Certificate2 certificate, CancellationToken token = new CancellationToken());

        /// <inheritdoc cref="Decrypt{T}(Stream,X509Certificate2,CancellationToken)"/>
        Task<T> DecryptAsync<T>(byte[] bytes, X509Certificate2 certificate, CancellationToken token = new CancellationToken());
    }
}
