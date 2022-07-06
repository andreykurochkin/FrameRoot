using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Options;
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
    private IDateTimeProvider _dateTimeProvider = new DateTimeNowProvider();
    private ISecurityTokenProvider _securityTokenProvider;
    private readonly JwtOptions _jwtOptions;
    private readonly IRefreshTokenProvider _refreshTokenProvider;

    public IdentityServiceTests()
    {
        _jwtOptions = new JwtOptions
        {
            Secret = "01234567890123456789012345678912",
            TokenLifeTime = new TimeSpan(0, 0, 15),
        };
        _passwordValidator = new DefaultPasswordValidator(_hashProvider);
        _securityTokenProvider = new DefaultSecurityTokenProvider(_jwtOptions, _dateTimeProvider);
        _refreshTokenProvider = new DefaultRefreshTokenProvider(_dateTimeProvider);
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
                   tokenValidationParameters: null!,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: null!,
                   refreshTokenProvider: null!);

        var result = await _sut.LoginAsync(Email, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain(expectedErrorMessage);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenProvidedPasswordAndStoredPasswordDontMatch()
    {
        var expectedErrorMessage = "Bad login/password pair";
        var identityUser = new IdentityUser
        {
            Password = Password,
            Salt = _saltProvider.GetSalt(),
        };
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(identityUser);
        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: null!,
                   dateTimeProvider: null!,
                   tokenValidationParameters: null!,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: null!,
                   refreshTokenProvider: null!);
        var randomPassword = Guid.NewGuid().ToString();

        var result = await _sut.LoginAsync(Email, randomPassword);

        result.Should().BeOfType<AuthenticationResult>();
        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain(expectedErrorMessage);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnSuccededAuthenticationResult_WhenDataIsValid()
    {
        var salt = _saltProvider.GetSalt();
        var saltAsBytes = Encoding.ASCII.GetBytes(salt);
        var hashedPassword = await _hashProvider.GetHashAsync(Password, saltAsBytes);
        var identityUser = new IdentityUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = Email,
            Password = hashedPassword,
            Salt = salt,
        };
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(identityUser);
        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: _jwtOptions,
                   dateTimeProvider: _dateTimeProvider,
                   tokenValidationParameters: null!,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: _securityTokenProvider,
                   refreshTokenProvider: _refreshTokenProvider);
        
        var result = await _sut.LoginAsync(Email, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Succeded.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
    }
}
