using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using Frame.UnitTests.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;
public class DefaultSecurityTokenProviderTests
{
    DefaultSecurityTokenProvider _sut = null!;
    private readonly JwtOptions _jwtOptions = null!;
    private readonly IDateTimeProvider _dateTimeProvider = new DateTimeNowProvider();
    private readonly ITestOutputHelper _testOutputHelper;

    public DefaultSecurityTokenProviderTests(ITestOutputHelper testOutputHelper)
    {
        _jwtOptions = new JwtOptions
        {
            Secret = "01234567890123456789012345678912",
            TokenLifeTime = new TimeSpan(0, 0, 15),
        };
        _sut = new DefaultSecurityTokenProvider(_jwtOptions, _dateTimeProvider);
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void GetAccessToken_ShouldGenerateToken_WhenDataIsValid()
    {
        var identityUser = new Frame.Domain.IdentityUser
        { 
            Id = Guid.NewGuid().ToString(),
            Email = "test@test.com",
        };

        var result = _sut.GetSecurityToken(identityUser);

        result.Should().NotBeNull();
    }

    [Fact]
    public void GetAccessToken_ShouldThrow_WhenEmailIsNull()
    {
        var identityUser = new Frame.Domain.IdentityUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = null!,
        };

        var func = () => _sut.GetSecurityToken(identityUser);

        func.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void GetAccessToken_ShouldThrow_WhenTokenExpIsBeforeDateTimeUtcNow()
    {
        var cashedDateTimeMinus10Minutes = DateTime.UtcNow.AddSeconds(-600);
        var mockTokenExpirationDateTimeProvider = new Mock<IDateTimeProvider>();
        mockTokenExpirationDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(cashedDateTimeMinus10Minutes);
        _sut = new DefaultSecurityTokenProvider(_jwtOptions, mockTokenExpirationDateTimeProvider.Object);

        var identityUser = IdentityUserHelper.GetOne();

        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, identityUser.Email),
            new Claim(JwtRegisteredClaimNames.Email, identityUser.Email),
            new Claim("identityUserId", identityUser.Id.ToString()),
        };

        byte[] key = Encoding.ASCII.GetBytes(_jwtOptions.Secret);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = mockTokenExpirationDateTimeProvider.Object.GetDateTime().ToUniversalTime(),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        };


        var func = () => new JwtSecurityTokenHandler().CreateToken(tokenDescriptor);
        func.Should().NotThrow<ArgumentException>();
    }

    [Fact]
    public void AlterGetAccessToken_ShouldThrow_WhenTokenExpIsBeforeDateTimeUtcNow()
    {
        var cashedDateTimeMinus10Minutes = DateTime.UtcNow.AddSeconds(-600);
        var mockTokenExpirationDateTimeProvider = new Mock<IDateTimeProvider>();
        mockTokenExpirationDateTimeProvider.Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(cashedDateTimeMinus10Minutes);
        _sut = new DefaultSecurityTokenProvider(_jwtOptions, mockTokenExpirationDateTimeProvider.Object);

        var identityUser = IdentityUserHelper.GetOne();

        _sut = new DefaultSecurityTokenProvider(_jwtOptions, mockTokenExpirationDateTimeProvider.Object);
        var t = _sut.GetSecurityToken(identityUser);
    }
}
