using FluentAssertions;
using Frame.Infrastructure.Providers;
using System.Text;
using Xunit;

namespace Frame.UnitTests;
public class DefaultHashProviderTests
{
    private readonly DefaultHashProvider _sut = new DefaultHashProvider();
    private readonly DefaultSaltProvider _saltProvider = new DefaultSaltProvider();

    [Fact]
    public void GetHash_ShouldGenerateNotNullHash_WhenDataIsValid()
    {
        const string password = "password";
        var salt = _saltProvider.GetSalt();
        var saltAsBytes = Encoding.ASCII.GetBytes(salt);

        var result = _sut.GetHash(password, saltAsBytes);

        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetHash_ShouldGenerateDifferentHashes_WhenPasswordsAreSameAndSaltsAreDifferent()
    {
        const string password1 = "password";
        var salt1 = _saltProvider.GetSalt();
        var saltAsBytes1 = Encoding.ASCII.GetBytes(salt1);

        const string password2 = "password";
        var salt2 = _saltProvider.GetSalt();
        var saltAsBytes2 = Encoding.ASCII.GetBytes(salt2);

        var result1 = _sut.GetHash(password1, saltAsBytes1);
        var result2 = _sut.GetHash(password2, saltAsBytes2);

        result1.Should().NotBe(result2);
    }

    [Fact]
    public void GetHash_ShouldGenerateDifferentHashes_WhenPasswordsAreDifferentAndSaltsAreDifferent()
    {
        const string password1 = "password1";
        var salt1 = _saltProvider.GetSalt();
        var saltAsBytes1 = Encoding.ASCII.GetBytes(salt1);

        const string password2 = "password2";
        var salt2 = _saltProvider.GetSalt();
        var saltAsBytes2 = Encoding.ASCII.GetBytes(salt2);

        var result1 = _sut.GetHash(password1, saltAsBytes1);
        var result2 = _sut.GetHash(password2, saltAsBytes2);

        result1.Should().NotBe(result2);
    }

    [Fact]
    public void GetHash_ShouldGenerateDifferentHashes_WhenPasswordsAreDifferentAndSaltsAreSame()
    {
        const string password1 = "password1";
        var salt1 = _saltProvider.GetSalt();
        var saltAsBytes1 = Encoding.ASCII.GetBytes(salt1);

        const string password2 = "password2";
        var salt2 = salt1;
        var saltAsBytes2 = Encoding.ASCII.GetBytes(salt2);

        var result1 = _sut.GetHash(password1, saltAsBytes1);
        var result2 = _sut.GetHash(password2, saltAsBytes2);

        result1.Should().NotBe(result2);
    }

    [Fact]
    public void GetHash_ShouldGenerateSameHashes_WhenPasswordsAreSameAndSaltsAreSame()
    {
        const string password1 = "password";
        var salt1 = _saltProvider.GetSalt();
        var saltAsBytes1 = Encoding.ASCII.GetBytes(salt1);

        const string password2 = "password";
        var salt2 = salt1;
        var saltAsBytes2 = Encoding.ASCII.GetBytes(salt2);

        var result1 = _sut.GetHash(password1, saltAsBytes1);
        var result2 = _sut.GetHash(password2, saltAsBytes2);

        result1.Should().Be(result2);
    }
}
