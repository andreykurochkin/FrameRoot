using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Validators;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Frame.UnitTests;
public class DefaultPasswordValidatorTests
{
    private readonly DefaultPasswordValidator _sut;
    private readonly DefaultHashProvider _hashProvider = new DefaultHashProvider();
    private readonly DefaultSaltProvider _saltProvider = new DefaultSaltProvider();

    public DefaultPasswordValidatorTests()
    {
        _sut = new DefaultPasswordValidator(_hashProvider);
    }

    [Fact]
    public async Task ValidateAsync_ShouldReturnSuccessIdentityResult_WhenPasswordsAreDifferent()
    {
        var salt = _saltProvider.GetSalt();
        var saltAsBytes = Encoding.ASCII.GetBytes(salt);
        const string password = "password";
        var hashedPassword = await _hashProvider.GetHashAsync(password, saltAsBytes);
        var identityUser = new Frame.Domain.IdentityUser
        { 
            Password = hashedPassword,
            Salt = salt,
        };

        var result = await _sut.ValidateAsync(identityUser, password);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_ShouldReturnFailedIdentityResultWithExpectedIdentityError_WhenPasswordsAreDifferent()
    {
        var salt = _saltProvider.GetSalt();
        var saltAsBytes = Encoding.ASCII.GetBytes(salt);
        const string password = "password";
        var hashedPassword = await _hashProvider.GetHashAsync(password, saltAsBytes);
        var identityUser = new Frame.Domain.IdentityUser
        {
            Password = hashedPassword,
            Salt = salt,
        };
        var anotherPassword = "another password";
        const string expectedErrorCode = "";
        const string expectedErrorDescription = "Bad login/password pair";

        var result = await _sut.ValidateAsync(identityUser, anotherPassword);

        result.Succeeded.Should().BeFalse();
        result.Errors.Any().Should().BeTrue();
        result.Errors.First().Code.Should().Be(expectedErrorCode);
        result.Errors.First().Description.Should().Be(expectedErrorDescription);
    }
}
