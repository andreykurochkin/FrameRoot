using FluentAssertions;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.UnitTests.Fixtures;
using Frame.UnitTests.Helpers;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;

[Collection("TokenSpecific Collection")]
public class JwtSecurityTokenHandlerTests : IClassFixture<TokenSpecificFixture>
{
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly TokenSpecificFixture _fixture;
    private readonly JwtSecurityTokenHandler _sut = new();

    public JwtSecurityTokenHandlerTests(ITestOutputHelper testOutputHelper, TokenSpecificFixture fixture)
    {
        _testOutputHelper = testOutputHelper;
        _fixture = fixture;
    }

    [Fact]
    public void CreateToken_ShouldThrow_WhenFirstExpiryDateThenDateTimeNow()
    {
        Action act = () => _sut.CreateToken(_fixture.ExpiredSecurityTokenDescriptor);
        
        act.Should().Throw<ArgumentException>().WithMessage("*IDX12401*");
    }

    [Fact]
    public void ValidateToken_ShouldThrow_WhenFirstTokenExpiresAndThenWaitForMoreThenSkewSecondsAndThenValidate()
    {
        var willExpireInTwoSeconds = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(_fixture.Claims),
            Expires = DateTime.UtcNow.AddSeconds(1),
            SigningCredentials = _fixture.SigningCredentials,
        };
        var securityToken = _sut.CreateToken(willExpireInTwoSeconds);
        var  token = _sut.WriteToken(securityToken);
        Task.Delay(TimeSpan.FromSeconds(6)).Wait();

        var tokenValidationParameters = _fixture.TokenValidationParameters;
        tokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(2);
        Action act = () => _sut.ValidateToken(token, tokenValidationParameters, out var validatedSecurityToken);

        act.Should().Throw<SecurityTokenExpiredException>();
    }

    [Fact]
    public void ValidateToken_ShouldThrow_WhenTokenIsExpired()
    {
        Action act = () => _sut.ValidateToken(_fixture.ExpiredToken, _fixture.TokenValidationParameters, out var validatedSecurityToken);

        act.Should().Throw<SecurityTokenExpiredException>().WithMessage("*IDX10223*");
    }
}
