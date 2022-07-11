using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using Frame.UnitTests.Helpers;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests.Fixtures;
public class TokenSpecificFixture
{
    public DateTime UtcNow { get; private set; }
    public DateTime TenMinutesBefore { get; private set; }
    public Mock<IDateTimeProvider> mockDateTimeProvider { get; private set; } = new();
    public JwtOptions JwtOptions { get; private set; }
    public SigningCredentials SigningCredentials { get; private set; }
    public SecurityTokenDescriptor ExpiredSecurityTokenDescriptor { get; private set; }
    public TokenValidationParameters TokenValidationParameters { get; private set; } 

    public string ExpiredToken { get; private set; }
    public string TokenWithoutIdentityUserId { get; private set; }

    public RefreshToken ExpiredRefreshToken { get; private set; }
    public RefreshToken InvalidatedRefreshToken { get; private set; }
    public RefreshToken UsedRefreshToken { get; private set; }
    public RefreshToken ValidRefreshToken { get; private set; }

    public const string Email = "test@test.com";
    public const string Password = "password";

    public List<Claim> Claims { get; private set; }
    
    public TokenSpecificFixture()
    {
        ExpiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJiNGU1YTFmYi1hODE1LTQ4N2ItYTg0OC1iMDZjYzRhNGMzZDEiLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwiaWRlbnRpdHlVc2VySWQiOiIyZDc5NjE5Zi01MzRhLTRhNGEtOTJhNi1hZmUyNjljYTYwZGQiLCJuYmYiOjE2NTcyNjkyNTcsImV4cCI6MTY1NzI2OTI1OSwiaWF0IjoxNjU3MjY5MjU3fQ.S6sGap0trL2euXx--_XmnVPwynyYW97sJ5HpASunuBs";
        UtcNow = DateTime.UtcNow;
        TenMinutesBefore = UtcNow.AddMinutes(-10);
        mockDateTimeProvider
            .Setup(dateTimeProvider => dateTimeProvider.GetDateTime())
            .Returns(TenMinutesBefore);
        Claims = new List<Claim>()
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
        TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(JwtOptions.Secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            RequireExpirationTime = false,
            ValidateLifetime = false,
        };
        ExpiredSecurityTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(Claims),
            Expires = mockDateTimeProvider.Object.GetDateTime(),
            SigningCredentials = SigningCredentials,
        };
        TokenWithoutIdentityUserId = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJiNGU1YTFmYi1hODE1LTQ4N2ItYTg0OC1iMDZjYzRhNGMzZDEiLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwibmJmIjoxNjU3MjY5MjU3LCJleHAiOjE2NTcyNjkyNTksImlhdCI6MTY1NzI2OTI1N30.fq3lxfxDdp8dT4Bm-XzKdJ9Pe7scGOUSl_96nBIF1HM";
        ExpiredRefreshToken = new RefreshToken
        {
            User = IdentityUserHelper.GetOne(),
            CreationDate = UtcNow,
            ExpiryDate = UtcNow.AddDays(-1),
            Invalidated = false,
            JwtId = Guid.NewGuid().ToString(),
            Token = ExpiredToken,
            UserId = IdentityUserHelper.GetOne().Id,
        };
        InvalidatedRefreshToken = new RefreshToken
        {
            User = IdentityUserHelper.GetOne(),
            CreationDate = UtcNow,
            ExpiryDate = UtcNow.AddDays(1),
            Invalidated = true,
            JwtId = Guid.NewGuid().ToString(),
            Token = ExpiredToken,
            UserId = IdentityUserHelper.GetOne().Id,
        };
        ValidRefreshToken = new RefreshToken
        {
            User = IdentityUserHelper.GetOne(),
            CreationDate = UtcNow,
            ExpiryDate = UtcNow.AddDays(1),
            Invalidated = false,
            JwtId = Guid.NewGuid().ToString(),
            Token = ExpiredToken,
            UserId = IdentityUserHelper.GetOne().Id,
        };
        UsedRefreshToken = new RefreshToken
        {
            User = IdentityUserHelper.GetOne(),
            CreationDate = UtcNow,
            ExpiryDate = UtcNow.AddDays(1),
            Invalidated = false,
            JwtId = Guid.NewGuid().ToString(),
            Token = ExpiredToken,
            UserId = IdentityUserHelper.GetOne().Id,
            Used = true,
        };
    }
}

[CollectionDefinition("TokenSpecific Collection")]
public class TokenSpecificCollection : ICollectionFixture<TokenSpecificFixture> { }
