using FluentAssertions;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.UnitTests.Helpers;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
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
public class DateTimeUtcNowFixture
{
    public DateTime UtcNow { get; private set; }
    public DateTime TenMinutesBefore { get; private set; }
    public Mock<IDateTimeProvider> mockDateTimeProvider { get; private set; } = new();
    public JwtOptions JwtOptions { get; private set; }
    public SigningCredentials SigningCredentials { get; private set; }
    public SecurityTokenDescriptor SecurityTokenDescriptor { get; private set; }
    public List<Claim> Claims { get; private set; }
    public DateTimeUtcNowFixture()
    {
        UtcNow = DateTime.UtcNow;
        TenMinutesBefore = UtcNow.AddMinutes(-10);
        mockDateTimeProvider
            .Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(TenMinutesBefore);
        var claims = new Claim[]
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, IdentityUserHelper.GetOne().Email),
            new Claim(JwtRegisteredClaimNames.Email, IdentityUserHelper.GetOne().Email),
            new Claim("identityUserId", IdentityUserHelper.GetOne().Id.ToString()),
        };
        JwtOptions = new JwtOptions
        {
            Secret = "01234567890123456789012345678912",
            TokenLifeTime = new TimeSpan(0, 0, 15),
        };
        byte[] key = Encoding.ASCII.GetBytes(JwtOptions.Secret);
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature);
        SecurityTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = mockDateTimeProvider.Object.GetDateTime(),
            SigningCredentials = SigningCredentials,
        };
    }
}

public class JwtSecurityTokenHandlerTests : IClassFixture<DateTimeUtcNowFixture>
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly DateTimeUtcNowFixture _fixture;

    public JwtSecurityTokenHandlerTests(ITestOutputHelper testOutputHelper, DateTimeUtcNowFixture fixture)
    {
        _testOutputHelper = testOutputHelper;
        _fixture = fixture;
    }

    [Fact]
    public void FirstTest() => _testOutputHelper.WriteLine(_fixture.UtcNow.Ticks.ToString());

    [Fact]
    public void SecondTest() => _testOutputHelper.WriteLine(_fixture.UtcNow.Ticks.ToString());

    // should throw same error when
    // time conditions [0 ... tokenExpiredDateTime ... DateTimeUctNow]
    // 1. detemine methods that throw error [ TokenCreate, TokenValidate ]
    // 01. how to unit test shared member
    // 02. how to use traits
    // 03. how to use constraints
}
