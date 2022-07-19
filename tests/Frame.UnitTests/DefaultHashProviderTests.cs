using FluentAssertions;
using Frame.Infrastructure.Providers;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Frame.UnitTests;
public class DefaultHashProviderTests
{
    private readonly DefaultHashProvider _sut = new DefaultHashProvider();
    private readonly DefaultSaltProvider _saltProvider = new DefaultSaltProvider();

    [Fact]
    public async Task GetHash_ShouldGenerateNotNullHash_WhenDataIsValid()
    {
        const string password = "password";
        var salt = _saltProvider.GetSalt();
        var saltAsBytes = Encoding.ASCII.GetBytes(salt);

        var result = await _sut.GetHashAsync(password, saltAsBytes);

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

        var task1 = _sut.GetHashAsync(password1, saltAsBytes1);
        var task2 = _sut.GetHashAsync(password2, saltAsBytes2);
        Task.WhenAll(task1, task2);
        var result1 = task1.Result;
        var result2 = task2.Result;

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

        var task1 = _sut.GetHashAsync(password1, saltAsBytes1);
        var task2 = _sut.GetHashAsync(password2, saltAsBytes2);
        Task.WhenAll(task1, task2);
        var result1 = task1.Result;
        var result2 = task2.Result;

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

        var task1 = _sut.GetHashAsync(password1, saltAsBytes1);
        var task2 = _sut.GetHashAsync(password2, saltAsBytes2);
        Task.WhenAll(task1, task2);
        var result1 = task1.Result;
        var result2 = task2.Result;

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

        var task1 = _sut.GetHashAsync(password1, saltAsBytes1);
        var task2 = _sut.GetHashAsync(password2, saltAsBytes2);
        Task.WhenAll(task1, task2);
        var result1 = task1.Result;
        var result2 = task2.Result;

        result1.Should().Be(result2);
    }
}
