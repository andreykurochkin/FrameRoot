using FluentAssertions;
using FluentValidation;
using Frame.Contracts.V1.Requests;
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
    private ISaltProvider _saltProvider = new DefaultSaltProvider();
    private IHashProvider _hashProvider = new DefaultHashProvider();
    private IPasswordHashValidator _passwordValidator = null!;
    private IDateTimeProvider _dateTimeProvider = new DateTimeNowProvider();
    private ISecurityTokenProvider _securityTokenProvider;
    private readonly IRefreshTokenProvider _refreshTokenProvider;
    ITestOutputHelper _testOutputHelper;
    private Mock<IRefreshTokenRepository> _mockRefreshTokenRepository = new();
    private readonly IValidator<UserSignupRequest> _userSignupRequestValidator;
    private readonly IIdentityUserProvider _identityUserProvider;
    public IdentityServiceTests(ITestOutputHelper testOutputHelper, TokenSpecificFixture fixture)
    {
        _testOutputHelper = testOutputHelper;

        _fixture = fixture;
        _passwordValidator = new DefaultPasswordValidator(_hashProvider);
        _securityTokenProvider = new DefaultSecurityTokenProvider(_fixture.JwtOptions, _dateTimeProvider);
        _refreshTokenProvider = new DefaultRefreshTokenProvider(_dateTimeProvider);
        _userSignupRequestValidator = new UserSignupRequestValidator();
        _identityUserProvider = new DefaultIdentityUserProvider(_saltProvider, _hashProvider);

        //  if required unit may create it`s own _sut
        _sut = new IdentityService(
            passwordHashValidator: _passwordValidator,
            jwtOptions: _fixture.JwtOptions,
            dateTimeProvider: _dateTimeProvider,
            tokenValidationParameters: _fixture.TokenValidationParameters,
            refreshTokenRepository: _mockRefreshTokenRepository.Object,
            identityUserRepository: _mockIdentityUserRepository.Object,
            securityTokenProvider: _securityTokenProvider,
            refreshTokenProvider: _refreshTokenProvider,
            userSignupRequestValidator: _userSignupRequestValidator,
            identityUserProvider: _identityUserProvider);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenUserDoesNotExist()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetNull);

        var result = await _sut.LoginAsync(TokenSpecificFixture.Email, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("User doesn`t exist");
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenProvidedPasswordAndStoredPasswordDontMatch()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetOne());

        var result = await _sut.LoginAsync(TokenSpecificFixture.Email, "new password");

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Bad login/password pair");
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnSuccededAuthenticationResult_WhenDataIsValid()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetOne(TokenSpecificFixture.Email, TokenSpecificFixture.Password));

        var result = await _sut.LoginAsync(TokenSpecificFixture.Email, TokenSpecificFixture.Password);

        result.Succeded.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenTokenIsNull()
    {
        var result = await _sut.RefreshTokenAsync(null, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Invalid token");
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a jwt at all")]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenTokenFormatIsNotValid(string token)
    {
        var result = await _sut.RefreshTokenAsync(token, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Invalid token format");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenAccessTokenHasNotExpired()
    {
        var token = (await _sut.GenerateAuthenticationResultForUserAsync(IdentityUserHelper.GetOne())).AccessToken;

        var result = await _sut.RefreshTokenAsync(token, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Token hasn`t expired yet");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenPersistentDoesNotHaveRefreshTokenWithSpecifiedJwtId()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync((RefreshToken)null!);

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("This refresh token doesn`t exit");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenRefreshTokenExpired()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync(_fixture.ExpiredRefreshToken);

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("This refresh token has expired");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenTokenDoesNotHaveClaimWithTypeIdentityUserId()
    {
        var result = await _sut.RefreshTokenAsync(_fixture.TokenWithoutIdentityUserId, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("Claim identityUserId is required");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenRefreshTokenInvalidated()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync(_fixture.InvalidatedRefreshToken);

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("This refresh token has been invalidated");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnFailedAuthenticationResult_WhenRefreshTokenUsed()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync(_fixture.UsedRefreshToken);

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, TokenSpecificFixture.Password);

        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain("This refresh token has been used");
    }

    [Fact]
    public async Task RefreshTokenAsync_ShouldReturnSuccededAuthenticationResult_WhenDataIsValid()
    {
        _mockRefreshTokenRepository
            .Setup(repository => repository.SaveChangesAsync(It.IsAny<RefreshToken>()));
        _mockRefreshTokenRepository
            .Setup(repository => repository.GetRefreshTokenByJwtIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync(_fixture.ValidRefreshToken);
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByIdAsync(It.IsNotNull<string>()))
            .ReturnsAsync(IdentityUserHelper.GetOne(TokenSpecificFixture.Email, TokenSpecificFixture.Password));

        var result = await _sut.RefreshTokenAsync(_fixture.ExpiredToken, TokenSpecificFixture.Password);

        result.Succeded.Should().BeTrue();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SignupAsync_ShouldFail_WhenPasswordAndConfirmPasswordAreSame()
    {
        _mockIdentityUserRepository
            .Setup(repository => repository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync((IdentityUser)null!);

        var result = await _sut.SignupAsync(TokenSpecificFixture.Email, TokenSpecificFixture.Password, TokenSpecificFixture.Password, "John", "Smith");

        result.Succeded!.Should().BeFalse();
    }
}
