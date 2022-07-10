using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Validators;
using Frame.Infrastructure.Validators.Base;
using Frame.UnitTests.Fixtures;
using Frame.UnitTests.Helpers;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;

[Collection("TokenSpecific Collection")]
public class IdentityServiceTests : IClassFixture<Fixtures.TokenSpecificFixture>
{
    private readonly TokenSpecificFixture _fixture;
    private IdentityService _sut = null!;
    private Mock<IIdentityUserRepository> _mockIdentityUserRepository = new();
    const string Email = "test@test.com";
    const string Password = "password";
    private ISaltProvider _saltProvider = new DefaultSaltProvider();
    private IHashProvider _hashProvider = new DefaultHashProvider();
    private IPasswordValidator _passwordValidator = null!;
    private IDateTimeProvider _dateTimeProvider = new DateTimeNowProvider();
    private ISecurityTokenProvider _securityTokenProvider;
    private readonly IRefreshTokenProvider _refreshTokenProvider;
    ITestOutputHelper _testOutputHelper;
    private Mock<IRefreshTokenRepository> _mockRefreshTokenRepository = new();

    public IdentityServiceTests(ITestOutputHelper testOutputHelper, TokenSpecificFixture fixture)
    {
        _testOutputHelper = testOutputHelper;

        _fixture = fixture;
        _passwordValidator = new DefaultPasswordValidator(_hashProvider);
        _securityTokenProvider = new DefaultSecurityTokenProvider(_fixture.JwtOptions, _dateTimeProvider);
        _refreshTokenProvider = new DefaultRefreshTokenProvider(_dateTimeProvider);

        //  if required unit may create it`s own _sut
        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: _fixture.JwtOptions,
                   dateTimeProvider: _dateTimeProvider,
                   tokenValidationParameters: _fixture.TokenValidationParameters,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: _securityTokenProvider,
                   refreshTokenProvider: _refreshTokenProvider,
                   refreshTokenRepository: _mockRefreshTokenRepository.Object);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenUserDoesNotExist()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetNull);

        var result = await _sut.LoginAsync(Email, Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("User doesn`t exist");
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenProvidedPasswordAndStoredPasswordDontMatch()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetOne());

        var result = await _sut.LoginAsync(Email, "new password");

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Bad login/password pair");
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnSuccededAuthenticationResult_WhenDataIsValid()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetOne(Email, Password));
        
        var result = await _sut.LoginAsync(Email, Password);

        result.Succeded.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenTokenIsNull()
    {
        var result = await _sut.RefreshTokenAsync(null, Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Invalid token");
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a jwt at all")]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenTokenFormatIsNotValid(string token)
    {
        var result = await _sut.RefreshTokenAsync(token, Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Invalid token format");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenAccessTokenHasNotExpired()
    {
        var token = (await _sut.GenerateAuthenticationResultForUserAsync(IdentityUserHelper.GetOne())).AccessToken;

        var result = await _sut.RefreshTokenAsync(token, Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Token hasn`t expired yet");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenPersistentDoesNotHaveRefreshTokenWithSpecifiedJwtId()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync((RefreshToken)null!);

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("This refresh token doesn`t exit");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenRefreshTokenExpired()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync((RefreshToken)null!);

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("This refresh token doesn`t exit");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenAccessTokenExpired()
    {
        var cashedDateTime = DateTime.UtcNow;
        var mockCurrentDateTimeProvider = new Mock<IDateTimeProvider>();
        mockCurrentDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(cashedDateTime);
        
        var timeGap = _fixture.JwtOptions.TokenLifeTime.TotalSeconds - 10;
        var cashedDateTimeMinus10Minutes = cashedDateTime.AddSeconds(-1*timeGap);

        var mockTokenExpirationDateTimeProvider = new Mock<IDateTimeProvider>();
        mockTokenExpirationDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(cashedDateTimeMinus10Minutes);

        var tokenExpired = mockCurrentDateTimeProvider.Object.GetDateTime() > mockTokenExpirationDateTimeProvider.Object.GetDateTime();
        if (!tokenExpired) throw new ArgumentException();

        _sut = new IdentityService(passwordValidator: _passwordValidator,
                   jwtOptions: _fixture.JwtOptions,
                   dateTimeProvider: mockCurrentDateTimeProvider.Object,
                   tokenValidationParameters: _fixture.TokenValidationParameters,
                   identityUserRepository: _mockIdentityUserRepository.Object,
                   securityTokenProvider: _securityTokenProvider,
                   refreshTokenProvider: _refreshTokenProvider,
                   refreshTokenRepository: _mockRefreshTokenRepository.Object);
        const string expectedErrorMessage = "Token hasn`t expired yet";

        //var mockTomorrowDateTimeProvider = new Mock<IDateTimeProvider>();
        //mockTomorrowDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
        //    .Returns(DateTime.Today.AddDays(1));
        //var yesterdayDateTimeProvider = mockTomorrowDateTimeProvider.Object;
        
        var identityUser = IdentityUserHelper.GetOne(Password);
        var securityToken = new DefaultSecurityTokenProvider(_fixture.JwtOptions, mockTokenExpirationDateTimeProvider.Object).GetSecurityToken(identityUser);
        var token = new JwtSecurityTokenHandler().WriteToken(securityToken);
        var result = await _sut.RefreshTokenAsync(token, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Errors.Should().Contain(expectedErrorMessage);
    }
}
