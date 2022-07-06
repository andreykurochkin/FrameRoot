using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Validators;
using Frame.Infrastructure.Validators.Base;
using Moq;
using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Frame.UnitTests;
public class IdentityServiceTests
{
    private IdentityService _sut = null!;
    private Mock<IIdentityUserRepository> _mockIdentityUserRepository = new();
    const string Email = "test@test.com";
    const string Password = "password";
    private ISaltProvider _saltProvider = new DefaultSaltProvider();
    private IHashProvider _hashProvider = new DefaultHashProvider();
    private IPasswordValidator _passwordValidator = null!;
    public IdentityServiceTests()
    {
        _passwordValidator = new DefaultPasswordValidator(_hashProvider);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenUserDoesNotExist()
    {
        var expectedErrorMessage = "User doesn`t exist";
        IdentityUser nullIdentityUser = null!;
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(nullIdentityUser);
        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: null!,
                   dateTimeProvider: null!,
                   httpContextAccessor: null!,
                   tokenValidationParameters: null!,
                   identityUserRepository: _mockIdentityUserRepository.Object);

        var result = await _sut.LoginAsync(Email, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain(expectedErrorMessage);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenProvidedPasswordAndStoredPasswordDontMatch()
    {
        var expectedErrorMessage = "Bad login/password pair";
        var salt = _saltProvider.GetSalt();
        var identityUser = new IdentityUser
        {
            Password = Password,
            Salt = salt,
        };
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(identityUser);
        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: null!,
                   dateTimeProvider: null!,
                   httpContextAccessor: null!,
                   tokenValidationParameters: null!,
                   identityUserRepository: _mockIdentityUserRepository.Object);
        var randomPassword = Guid.NewGuid().ToString();

        var result = await _sut.LoginAsync(Email, randomPassword);

        result.Should().BeOfType<AuthenticationResult>();
        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain(expectedErrorMessage);
    }
}
