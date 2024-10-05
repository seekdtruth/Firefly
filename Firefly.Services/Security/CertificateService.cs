using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Firefly.Core.Configurations;
using Firefly.Core.Services.Security;
using Firefly.Utilities.Extensions;
using Microsoft.Extensions.Logging;

namespace Firefly.Services.Security
{
    public class CertificateService : ICertificateService
    {
        private readonly CertificateClient _certificateClient;

        private readonly Dictionary<string, X509Certificate2> _certificateCollection = new Dictionary<string, X509Certificate2>();

        private readonly ILogger<CertificateService> _logger;

        public CertificateService(IFireflyConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<CertificateService>();

            _certificateClient = new CertificateClient(configuration.KeyVaultUri, configuration.KeyVaultCredential,
                new CertificateClientOptions()
                {
                    Retry =
                    {
                        Delay = TimeSpan.FromSeconds(1),
                        MaxDelay = TimeSpan.FromSeconds(1),
                        MaxRetries = 1,
                        Mode = RetryMode.Exponential
                    }
                });
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no certificate name is provided</exception>
        /// <exception cref="FileNotFoundException">Thrown when a certificate isn't found for provided <paramref name="certificateName"/></exception>
        public X509Certificate2 GetCertificate(string certificateName, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                if ( TryGetCertificate(certificateName, out var certificate) ) return certificate;

                var response = _certificateClient.GetCertificate(certificateName, cancellationToken).Value ?? throw new FileNotFoundException($"Unable to retrieve certificate: {certificateName}");
                var bytes = response.Cer.Any() ? response.Cer : throw new FileNotFoundException($"Certificate {certificateName} was empty");
                var cert = new X509Certificate2(bytes);

                _certificateCollection.Add(certificateName, cert);

                return cert;
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        /// <inheritdoc cref="GetCertificate(string, CancellationToken)"/>
        public async Task<X509Certificate2> GetCertificateAsync(string certificateName, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                if ( TryGetCertificate(certificateName, out var certificate) ) return certificate;

                _logger.LogInformation("Getting Certificate");
                certificateName = !certificateName.IsNullOrWhitespace() ? certificateName : throw new ArgumentNullException(nameof(certificateName));

                var task = await _certificateClient.GetCertificateAsync(certificateName, cancellationToken).ConfigureAwait(false);

                var keyVaultCertificateWithPolicy = task.Value ?? throw new FileNotFoundException($"Unable to retrieve certificate: {certificateName}");

                var bytes = keyVaultCertificateWithPolicy.Cer.Any()
                    ? keyVaultCertificateWithPolicy.Cer
                    : throw new FileNotFoundException($"Certificate {certificateName} was empty");

                var cert = new X509Certificate2(bytes) { FriendlyName = keyVaultCertificateWithPolicy.Name };

                return cert;
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
            finally
            {
                _logger.LogInformation($"Retrieval complete");
            }
        }

        public X509Certificate2 DownloadCertificate(string name, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                _logger.LogInformation($"Entering method {nameof(DownloadCertificateAsync)}");

                name = !name.IsNullOrWhitespace() ? name : throw new ArgumentNullException(nameof(name));

                var task = _certificateClient.DownloadCertificate(name);

                if ( task.GetRawResponse().IsError )
                {
                    _logger.LogError($"Response had error. {task.GetRawResponse().Status}: {task.GetRawResponse().ReasonPhrase}");
                    throw new FileNotFoundException($"Response had error. {task.GetRawResponse().Status}: {task.GetRawResponse().ReasonPhrase}");
                }

                if (task.HasValue) return task.Value;

                _logger.LogError("Response has no value");
                throw new FileNotFoundException("No response was received");
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
            finally
            {
                _logger.LogInformation($"Exiting method {nameof(DownloadCertificate)}");
            }
        }

        public async Task<X509Certificate2> DownloadCertificateAsync(string name, CancellationToken cancellationToken = new CancellationToken())
        {
            try
            {
                _logger.LogInformation($"Entering method {nameof(DownloadCertificateAsync)}");

                name = !name.IsNullOrWhitespace() ? name : throw new ArgumentNullException(nameof(name));

                var task = await _certificateClient.DownloadCertificateAsync(name).ConfigureAwait(false);

                if ( task.GetRawResponse().IsError )
                {
                    _logger.LogError($"Response had error. {task.GetRawResponse().Status}: {task.GetRawResponse().ReasonPhrase}");
                    throw new FileNotFoundException($"Response had error. {task.GetRawResponse().Status}: {task.GetRawResponse().ReasonPhrase}");
                }

                if ( !task.HasValue )
                {
                    _logger.LogError("Response has no value");
                    throw new FileNotFoundException("No response was received");
                }

                return task.Value;
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
            finally
            {
                _logger.LogInformation($"Exiting method {nameof(DownloadCertificateAsync)}");
            }
        }

        private bool TryGetCertificate(string certificateName, out X509Certificate2 certificate)
        {
            certificateName = !certificateName.IsNullOrWhitespace() ? certificateName : throw new ArgumentNullException(nameof(certificateName));
            certificate = _certificateCollection.ContainsKey(certificateName) ? _certificateCollection[certificateName] : new X509Certificate2();
            return _certificateCollection.ContainsKey(certificateName);
        }
    }
}