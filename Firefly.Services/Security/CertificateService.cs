using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Azure.Security.KeyVault.Certificates;

using Firefly.Core.Services.Security;
using Firefly.Utilities.Extensions;

using Microsoft.Extensions.Logging;

namespace Firefly.Services.Security
{
    /// <summary>
    /// Represents an implementation of an <see cref="ICertificateService"/>
    /// </summary>
    public class CertificateService : ICertificateService
    {
        private readonly CertificateClient _certificateClient;

        private readonly Dictionary<string, X509Certificate2> _certificateCollection = new Dictionary<string, X509Certificate2>();

        private readonly ILogger<CertificateService> _logger;

        /// <summary>
        /// Creates a new instance of a <see cref="CertificateService"/>
        /// </summary>
        /// <param name="client"></param>
        /// <param name="loggerFactory">The logger factory</param>
        /// <exception>Thrown when there is an error during instantiation</exception>
        public CertificateService(CertificateClient client, ILoggerFactory? loggerFactory)
        {
            loggerFactory ??= new LoggerFactory();
            _logger = loggerFactory.CreateLogger<CertificateService>();

            try
            {
                _certificateClient = client ?? throw new ArgumentNullException(nameof(client));
            } 
            catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException">Thrown when no certificate name is provided</exception>
        /// <exception cref="FileNotFoundException">Thrown when a certificate isn't found for provided <paramref name="certificateName"/></exception>
        public X509Certificate2 GetCertificate(string certificateName, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(CertificateService)} {nameof(GetCertificate)} {nameof(certificateName)}={certificateName}");

            try
            {
                if ( _certificateCollection.TryGetValue(certificateName, out var value) ) return value;

                var response = _certificateClient.GetCertificate(certificateName, cancellationToken);

                if ( !response.HasValue )
                {
                    var rawResponse = response.GetRawResponse();
                    throw new FileNotFoundException(
                        $"Failed to retrieve certificate: '{certificateName}'. Code={rawResponse.Status} Reason={rawResponse.ReasonPhrase}");
                }

                if ( !response.Value.Cer.Any() )
                {
                    throw new FileLoadException("Certificate contents are empty.");
                }

                var cer = response.Value.Cer.Any()
                    ? response.Value.Cer
                    : throw new FileNotFoundException($"Certificate {certificateName} was empty");

                var certificate = new X509Certificate2(cer) { FriendlyName = response.Value.Name };

                _certificateCollection.TryAdd(certificateName, certificate);

                return certificate;
            } catch ( Exception ex )
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        /// <inheritdoc cref="GetCertificate(string, CancellationToken)"/>
        public async Task<X509Certificate2> GetCertificateAsync(string certificateName, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(CertificateService)} {nameof(GetCertificateAsync)} {nameof(certificateName)}={certificateName}");

            try
            {
                certificateName = !certificateName.IsNullOrWhitespace() ? certificateName : throw new ArgumentNullException(nameof(certificateName));

                if ( _certificateCollection.TryGetValue(certificateName, out var value) ) return value;

                var response = await _certificateClient.GetCertificateAsync(certificateName, cancellationToken).ConfigureAwait(false);

                if (!response.HasValue)
                {
                    var rawResponse = response.GetRawResponse();
                    throw new FileNotFoundException(
                        $"Failed to retrieve certificate: '{certificateName}'. Code={rawResponse.Status} Reason={rawResponse.ReasonPhrase}");
                }

                if (!response.Value.Cer.Any())
                {
                    throw new FileLoadException("Certificate contents are empty.");
                }

                var cer = response.Value.Cer.Any()
                    ? response.Value.Cer
                    : throw new FileNotFoundException($"Certificate {certificateName} was empty");

                var certificate = new X509Certificate2(cer) { FriendlyName = response.Value.Name };

                _certificateCollection.TryAdd(certificateName, certificate);

                return certificate;
            } 
            catch ( Exception ex )
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        /// <inheritdoc />
        public X509Certificate2 DownloadCertificate(string certificateName, string? version = null, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(CertificateService)} {nameof(GetCertificate)} {nameof(certificateName)}={certificateName} {nameof(version)}={version}");

            try
            {
                certificateName = !certificateName.IsNullOrWhitespace() ? certificateName : throw new ArgumentNullException(nameof(certificateName));

                if (_certificateCollection.TryGetValue(certificateName, out var value) )
                    return value;

                var response = _certificateClient.DownloadCertificate(certificateName, version, cancellationToken);

                if ( !response.HasValue )
                {
                    var rawResponse = response.GetRawResponse();
                    throw new FileNotFoundException(
                        $"Failed to retrieve certificate: '{certificateName}'. Code={rawResponse.Status} Reason={rawResponse.ReasonPhrase}");
                }

                var certificate = response.Value;

                _certificateCollection.TryAdd(certificateName, certificate);

                return certificate;
            } 
            catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc />
        public async Task<X509Certificate2> DownloadCertificateAsync(string certificateName, string? version = null, CancellationToken cancellationToken = new CancellationToken())
        {
            _logger.LogInformation($"{nameof(CertificateService)} {nameof(GetCertificateAsync)} {nameof(certificateName)}={certificateName} {nameof(version)}={version}");

            try
            {
                certificateName = !certificateName.IsNullOrWhitespace() ? certificateName : throw new ArgumentNullException(nameof(certificateName));

                if ( _certificateCollection.TryGetValue(certificateName, out var value) )
                    return value;

                var response = await _certificateClient.DownloadCertificateAsync(certificateName, version, cancellationToken).ConfigureAwait(false);

                if ( !response.HasValue )
                {
                    var rawResponse = response.GetRawResponse();
                    throw new FileNotFoundException(
                        $"Failed to retrieve certificate: '{certificateName}'. Code={rawResponse.Status} Reason={rawResponse.ReasonPhrase}");
                }

                var certificate = response.Value;

                _certificateCollection.TryAdd(certificateName, certificate);

                return certificate;
            } 
            catch ( Exception ex )
            {
                _logger.LogError(ex, ex.Message);
                throw;
            }
        }
    }
}