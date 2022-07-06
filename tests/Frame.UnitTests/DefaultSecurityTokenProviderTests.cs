using FluentAssertions;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using System;
using System.IdentityModel.Tokens.Jwt;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;
public class DefaultSecurityTokenProviderTests
{
    ISecurityTokenProvider _sut = null!;
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
            Email = null,
        };

        var func = () => _sut.GetSecurityToken(identityUser);

        func.Should().Throw<ArgumentNullException>();
    }
}
