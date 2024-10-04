using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Threading;

namespace Firefly.Core.Services.Security
{
    public interface ICertificateService
    {
        /// <summary>
        /// Retrieves a public key <see cref="X509Certificate2" />
        /// </summary>
        /// <param name="name">Name of certificate to retrieve</param>
        /// <returns>Requested <see cref="X509Certificate2" /></returns>
        X509Certificate2 GetCertificate(string name, CancellationToken cancellationToken = new CancellationToken());

        /// <inheritdoc cref="GetCertificate(string, CancellationToken)"/>
        Task<X509Certificate2> GetCertificateAsync(string name, CancellationToken cancellationToken = new CancellationToken());

        /// <summary>
        /// Retrieves a public and private keys <see cref="X509Certificate2" />
        /// </summary>
        /// <param name="name">Name of certificate to retrieve</param>
        /// <returns>Requested <see cref="X509Certificate2" /></returns>
        X509Certificate2 DownloadCertificate(string name, CancellationToken cancellationToken = new CancellationToken());

        /// <inheritdoc cref="DownloadCertificate(string, CancellationToken)"/>
        Task<X509Certificate2> DownloadCertificateAsync(string name, CancellationToken cancellationToken = new CancellationToken());
    }
}
