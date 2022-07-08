using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Validators;
using Frame.Infrastructure.Validators.Base;
using Frame.UnitTests.Helpers;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Frame.UnitTests;

[Collection("TokenSpecific Collection")]
public class IdentityServiceTests : IClassFixture<Fixtures.TokenSpecificFixture>
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
    private readonly TokenValidationParameters _tokenValidationParameters;

    public IdentityServiceTests()
    {
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

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenClaimsPrincipalTakenFromTokenIsNull()
    {
        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: _jwtOptions,
                   dateTimeProvider: _dateTimeProvider,
                   tokenValidationParameters: _tokenValidationParameters,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: _securityTokenProvider,
                   refreshTokenProvider: _refreshTokenProvider);
        const string expectedErrorMessage = "Invalid token";

        const string invalidToken = null!;
        var result = await _sut.RefreshTokenAsync(invalidToken, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Errors.Should().Contain(expectedErrorMessage);
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenAccessTokenExpired()
    {
        
        var cashedDateTime = DateTime.UtcNow;
        var mockCurrentDateTimeProvider = new Mock<IDateTimeProvider>();
        mockCurrentDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(cashedDateTime);
        
        var timeGap = _jwtOptions.TokenLifeTime.TotalSeconds - 10;
        var cashedDateTimeMinus10Minutes = cashedDateTime.AddSeconds(-1*timeGap);

        var mockTokenExpirationDateTimeProvider = new Mock<IDateTimeProvider>();
        mockTokenExpirationDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(cashedDateTimeMinus10Minutes);

        var tokenExpired = mockCurrentDateTimeProvider.Object.GetDateTime() > mockTokenExpirationDateTimeProvider.Object.GetDateTime();
        if (!tokenExpired) throw new ArgumentException();

        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: _jwtOptions,
                   dateTimeProvider: mockCurrentDateTimeProvider.Object,
                   tokenValidationParameters: _tokenValidationParameters,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: _securityTokenProvider,
                   refreshTokenProvider: _refreshTokenProvider);
        const string expectedErrorMessage = "Token hasn`t expired yet";

        //var mockTomorrowDateTimeProvider = new Mock<IDateTimeProvider>();
        //mockTomorrowDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
        //    .Returns(DateTime.Today.AddDays(1));
        //var yesterdayDateTimeProvider = mockTomorrowDateTimeProvider.Object;
        
        var identityUser = IdentityUserHelper.GetOne(Password);
        var securityToken = new DefaultSecurityTokenProvider(_jwtOptions, mockTokenExpirationDateTimeProvider.Object).GetSecurityToken(identityUser);
        var token = new JwtSecurityTokenHandler().WriteToken(securityToken);
        var result = await _sut.RefreshTokenAsync(token, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Errors.Should().Contain(expectedErrorMessage);
    }
}
