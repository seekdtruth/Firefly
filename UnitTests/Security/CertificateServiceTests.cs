using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

using Firefly.Services.Security;

using FluentAssertions;

using Microsoft.Extensions.Logging.Abstractions;

using Moq;

namespace UnitTests.Security
{
    public class CertificateServiceTests
    {
        [Fact()]
        public void GetCertificate_ServiceAlreadyHasCertificate_PullsCertificateFromLocalStore()
        {
            var certName = "Certificate";
            var policy = CertificateModelFactory.CertificateProperties(name: certName);
            var generated = GenerateSelfSignedCertificate(certName);
            var certificate = CertificateModelFactory.KeyVaultCertificateWithPolicy(policy, cer: generated.RawData);

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.GetCertificate(certName, It.IsNotNull<CancellationToken>()))
                .Returns(Response.FromValue(certificate, Mock.Of<Response>()));

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());
        
            var cert = certService.GetCertificate(certName);
            cert = certService.GetCertificate(certName);

            cert.Should().NotBeNull();
            cert.RawData.Should().BeEquivalentTo(generated.RawData);
            mockClient.Invocations.Count.Should().Be(1);
        }

        [Fact()]
        public void GetCertificate_ClientDoesntHaveCertificate_ThrowsCorrectException()
        {
            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<KeyVaultCertificateWithPolicy>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var certName = "Certificate";

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.GetCertificate(certName, It.IsNotNull<CancellationToken>()))
                .Returns(mockResponse.Object);

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var exception = Record.Exception(() => certService.GetCertificate(certName));

            exception.Should().NotBeNull();
            exception.Message.Should().Be($"Failed to retrieve certificate: '{certName}'. Code=404 Reason=NotFound");
        }

        [Fact()]
        public async Task GetCertificateAsync_ServiceAlreadyHasCertificate_PullsCertificateFromLocalStore()
        {
            var certName = "Certificate";
            var policy = CertificateModelFactory.CertificateProperties(name: certName);
            var generated = GenerateSelfSignedCertificate(certName);
            var certificate = CertificateModelFactory.KeyVaultCertificateWithPolicy(policy, cer: generated.RawData);

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.GetCertificateAsync(certName, It.IsNotNull<CancellationToken>()))
                .ReturnsAsync(Response.FromValue(certificate, Mock.Of<Response>()));

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var cert = await certService.GetCertificateAsync(certName);
            cert = await certService.GetCertificateAsync(certName);

            cert.Should().NotBeNull();
            cert.RawData.Should().BeEquivalentTo(generated.RawData);
            mockClient.Invocations.Count.Should().Be(1);
        }

        [Fact()]
        public async Task GetCertificateAsync_ClientDoesntHaveCertificate_ThrowsCorrectException()
        {
            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<KeyVaultCertificateWithPolicy>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var certName = "Certificate";

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.GetCertificateAsync(certName, It.IsNotNull<CancellationToken>()))
                .ReturnsAsync(mockResponse.Object);

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var exception = await Record.ExceptionAsync(() => certService.GetCertificateAsync(certName));
            
            exception.Should().NotBeNull();
            exception.Message.Should().Be($"Failed to retrieve certificate: '{certName}'. Code=404 Reason=NotFound");
        }

        [Fact()]
        public void DownloadCertificate_ServiceAlreadyHasCertificate_PullsCertificateFromLocalStore()
        {
            var certName = "Certificate";
            var generated = GenerateSelfSignedCertificate(certName);

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.DownloadCertificate(
                    It.IsAny<string>(), 
                    It.IsAny<string>(),
                    It.IsNotNull<CancellationToken>()))
                .Returns(Response.FromValue(generated, Mock.Of<Response>()));

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var cert = certService.DownloadCertificate(certName);
            cert = certService.DownloadCertificate(certName);

            cert.Should().NotBeNull();
            cert.RawData.Should().BeEquivalentTo(generated.RawData);
            mockClient.Invocations.Count.Should().Be(1);
        }

        [Fact()]
        public void DownloadCertificate_ClientDoesntHaveCertificate_ThrowsCorrectException()
        {
            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<X509Certificate2>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var certName = "Certificate";

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.DownloadCertificate(
                    It.IsAny<string>(), 
                    It.IsAny<string>(), 
                    It.IsNotNull<CancellationToken>()))
                .Returns(mockResponse.Object);

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var exception = Record.Exception(() => certService.DownloadCertificate(certName));

            exception.Should().NotBeNull();
            exception.Message.Should().Be($"Failed to retrieve certificate: '{certName}'. Code=404 Reason=NotFound");
        }

        [Fact()]
        public async Task DownloadCertificateAsync_ServiceAlreadyHasCertificate_PullsCertificateFromLocalStore()
        {
            var certName = "Certificate";
            var generated = GenerateSelfSignedCertificate(certName);

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.DownloadCertificateAsync(
                    It.IsAny<string>(), 
                    It.IsAny<string>(),
                    It.IsNotNull<CancellationToken>()))
                .ReturnsAsync(Response.FromValue(generated, Mock.Of<Response>()));

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var cert = await certService.DownloadCertificateAsync(certName);
            cert = await certService.DownloadCertificateAsync(certName);

            cert.Should().NotBeNull();
            cert.RawData.Should().BeEquivalentTo(generated.RawData);
            mockClient.Invocations.Count.Should().Be(1);
        }

        [Fact()]
        public async Task DownloadCertificateAsync_ClientDoesntHaveCertificate_ThrowsCorrectException()
        {
            var certName = "Certificate";
            var generated = GenerateSelfSignedCertificate(certName);

            var mockClient = new Mock<CertificateClient>();
            mockClient.Setup(client => client.DownloadCertificateAsync(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsNotNull<CancellationToken>()))
                .ReturnsAsync(Response.FromValue(generated, Mock.Of<Response>()));

            var certService = new CertificateService(mockClient.Object, new NullLoggerFactory());

            var cert = await certService.DownloadCertificateAsync(certName);
            cert = await certService.DownloadCertificateAsync(certName);

            cert.Should().NotBeNull();
            cert.RawData.Should().BeEquivalentTo(generated.RawData);
            mockClient.Invocations.Count.Should().Be(1);
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(string name)
        {
            string secp256r1Oid = "1.2.840.10045.3.1.7";  //oid for prime256v1(7)  other identifier: secp256r1

            var ecdsa = ECDsa.Create(ECCurve.CreateFromValue(secp256r1Oid));

            var certRequest = new CertificateRequest($"CN={name}", ecdsa, HashAlgorithmName.SHA256);

            //add extensions to the request (just as an example)
            //add keyUsage
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

            // generate the cert and sign!
            X509Certificate2 generatedCert = certRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(10));

            //has to be turned into pfx or Windows at least throws a security credentials not found during sslStream.connectAsClient or HttpClient request...
            X509Certificate2 pfxGeneratedCert = new X509Certificate2(generatedCert.Export(X509ContentType.Pfx));

            return pfxGeneratedCert;
        }
    }
}