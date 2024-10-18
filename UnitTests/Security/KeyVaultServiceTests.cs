using System.Net;

using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;

using Firefly.Core.Configurations;
using Firefly.Services.Security;

using FluentAssertions;

using Microsoft.Extensions.Logging.Abstractions;

using Moq;

namespace UnitTests.Security
{
    public class KeyVaultServiceTests
    {
        [Fact]
        public void GetSecret_SecretExists_ServiceRetrievesFromDictionary()
        {
            // Arrange
            var keyVaultSecret = SecretModelFactory.KeyVaultSecret((new SecretProperties("SecretKey")), "SecretValue");

            var mockSecretClient = new Mock<SecretClient>();
            mockSecretClient.Setup(client => client.GetSecret(It.Is<string>(
                        name => name == keyVaultSecret.Name),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .Returns(Response.FromValue(keyVaultSecret, Mock.Of<Response>()));

            var service = new KeyVaultService(
                CreateConfigurationMock(),
                mockSecretClient.Object,
                new Mock<KeyClient>().Object,
                new NullLoggerFactory());

            // Act
            var initialResult = service.GetSecret("SecretKey", version: null);
            var secondResult = service.GetSecret("SecretKey", version: null);

            // Assert
            initialResult.Should().Be(keyVaultSecret);
            secondResult.Should().Be(keyVaultSecret);
            mockSecretClient.Invocations.Count.Should().Be(1);
        }

        [Fact]
        public async Task GetSecretAsync_SecretExists_ServiceRetrievesFromDictionary()
        {
            // Arrange
            var keyVaultSecret = SecretModelFactory.KeyVaultSecret((new SecretProperties("SecretKey")), "SecretValue");

            var mockSecretClient = new Mock<SecretClient>();
            mockSecretClient.Setup(client => client.GetSecretAsync(It.Is<string>(
                        name => name == keyVaultSecret.Name),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(Response.FromValue(keyVaultSecret, Mock.Of<Response>()));

            var service = new KeyVaultService(
                CreateConfigurationMock(),
                mockSecretClient.Object,
                new Mock<KeyClient>().Object,
                new NullLoggerFactory());

            // Act
            var initialResult = await service.GetSecretAsync("SecretKey", version: null);
            var secondResult = await service.GetSecretAsync("SecretKey", version: null);

            // Assert
            initialResult.Should().Be(keyVaultSecret);
            secondResult.Should().Be(keyVaultSecret);
            mockSecretClient.Invocations.Count.Should().Be(1);
        }

        [Fact]
        public void GetSecret_SecretDoesntExist_ThrowsException()
        {
            // Arrange
            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<KeyVaultSecret>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var mockSecretClient = new Mock<SecretClient>();
            mockSecretClient.Setup(client => client.GetSecret(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .Returns(mockResponse.Object);

            var service = new KeyVaultService(
                CreateConfigurationMock(),
                mockSecretClient.Object,
                new Mock<KeyClient>().Object,
                new NullLoggerFactory());

            // Act

            var record = Record.Exception(() => service.GetSecret("SecretKey", null));

            // Assert
            record.Should().NotBeNull();
            record.Message.Should().Be($"Failed to retrieve secret: 'SecretKey'. Code=404 Reason=NotFound");
        }

        [Fact]
        public async Task GetSecretAsync_SecretDoesntExist_ThrowsException()
        {
            // Arrange
            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<KeyVaultSecret>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var mockSecretClient = new Mock<SecretClient>();
            mockSecretClient.Setup(client => client.GetSecretAsync(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(mockResponse.Object);

            var service = new KeyVaultService(
                CreateConfigurationMock(),
                mockSecretClient.Object,
                new Mock<KeyClient>().Object,
                new NullLoggerFactory());

            // Act

            var record = await Record.ExceptionAsync(() => service.GetSecretAsync("SecretKey", null));

            // Assert
            record.Should().NotBeNull();
            record.Message.Should().Be($"Failed to retrieve secret: 'SecretKey'. Code=404 Reason=NotFound");
        }

        [Fact]
        public void GetKey_KeyExists_ServiceRetrievesFromDictionary()
        {
            //Arrange
            var keyName = "KeyName";
            var key = KeyModelFactory.KeyVaultKey(KeyModelFactory.KeyProperties(name: keyName),
                KeyModelFactory.JsonWebKey(KeyType.Rsa));

            var response = Response.FromValue(key, Mock.Of<Response>());

            var clientMock = new Mock<KeyClient>();
            clientMock.Setup(client => client.GetKey(It.IsAny<string>(), It.IsAny<string>(), It.IsNotNull<CancellationToken>()))
                .Returns(response);

            var service = new KeyVaultService(CreateConfigurationMock(), Mock.Of<SecretClient>(), clientMock.Object, new NullLoggerFactory());

            //Act
            var keyResponse = service.GetKey(keyName, null);
            keyResponse = service.GetKey(keyName, null);

            // Assert
            keyResponse.Should().Be(key);
            clientMock.Invocations.Should().HaveCount(1);
        }

        [Fact]
        public async Task GetKeyAsync_KeyExists_ServiceRetrievesFromDictionary()
        {
            //Arrange
            var keyName = "KeyName";
            var key = KeyModelFactory.KeyVaultKey(KeyModelFactory.KeyProperties(name: keyName),
                KeyModelFactory.JsonWebKey(KeyType.Rsa));

            var response = Response.FromValue(key, Mock.Of<Response>());

            var clientMock = new Mock<KeyClient>();
            clientMock.Setup(client => client.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsNotNull<CancellationToken>()))
                .ReturnsAsync(response);

            var service = new KeyVaultService(CreateConfigurationMock(), Mock.Of<SecretClient>(), clientMock.Object, new NullLoggerFactory());

            //Act
            var keyResponse = await service.GetKeyAsync(keyName, null);
            keyResponse = await service.GetKeyAsync(keyName, null);

            // Assert
            keyResponse.Should().Be(key);
            clientMock.Invocations.Should().HaveCount(1);
        }

        [Fact]
        public async Task GetKeyAsync_KeyDoesntExist_ThrowsException()
        {
            // Arrange
            var keyName = "SecretKey";
            
            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<KeyVaultKey>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var mockKeyClient = new Mock<KeyClient>();
            mockKeyClient.Setup(client => client.GetKeyAsync(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(mockResponse.Object);

            var service = new KeyVaultService(
                CreateConfigurationMock(),
                Mock.Of<SecretClient>(),
                mockKeyClient.Object,
                new NullLoggerFactory());

            // Act
            var record = await Record.ExceptionAsync(() => service.GetKeyAsync(keyName, null));

            // Assert
            record.Should().NotBeNull();
            record.Message.Should().Be($"Failed to retrieve key: '{keyName}'. Code=404 Reason=NotFound");
        }

        [Fact]
        public void GetKey_KeyDoesntExist_ThrowsException()
        {
            // Arrange
            var keyName = "SecretKey";

            var rawResponse = new Mock<Response>();
            rawResponse.Setup(response => response.Status).Returns((int) HttpStatusCode.NotFound);
            rawResponse.Setup(response => response.ReasonPhrase).Returns("NotFound");

            var mockResponse = new Mock<Response<KeyVaultKey>>();
            mockResponse.Setup(response => response.HasValue).Returns(false);
            mockResponse.Setup(response => response.GetRawResponse()).Returns(rawResponse.Object);

            var mockKeyClient = new Mock<KeyClient>();
            mockKeyClient.Setup(client => client.GetKey(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<CancellationToken>()))
                .Returns(mockResponse.Object);

            var service = new KeyVaultService(
                CreateConfigurationMock(),
                Mock.Of<SecretClient>(),
                mockKeyClient.Object,
                new NullLoggerFactory());

            // Act
            var record = Record.Exception(() => service.GetKey(keyName, null));

            // Assert
            record.Should().NotBeNull();
            record.Message.Should().Be($"Failed to retrieve key: '{keyName}'. Code=404 Reason=NotFound");
        }

        private IFireflyConfiguration CreateConfigurationMock()
        {
            var mock = new Mock<IFireflyConfiguration>();

            mock.Setup(config => config.KeyVaultUri).Returns(new Uri("https://someurl.com"));
            mock.Setup(config => config.KeyVaultName).Returns("KeyVaultName");
            mock.Setup(config => config.KeyVaultCredential).Returns(new DefaultAzureCredential());

            return mock.Object;
        }
    }
}
