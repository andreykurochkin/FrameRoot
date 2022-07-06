using FluentAssertions;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using System;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;
public class DefaultJwtProviderTests
{
    IJwtProvider _sut = null!;
    private readonly JwtOptions _jwtOptions = null!;
    private readonly IDateTimeProvider _dateTimeProvider = new DateTimeNowProvider();
    private readonly ITestOutputHelper _testOutputHelper;

    public DefaultJwtProviderTests(ITestOutputHelper testOutputHelper)
    {
        _jwtOptions = new JwtOptions
        {
            Secret = "01234567890123456789012345678912",
            TokenLifeTime = new TimeSpan(0, 0, 15),
        };
        _sut = new DefaultJwtProvider(_jwtOptions, _dateTimeProvider);
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

        var result = _sut.GetAccessToken(identityUser);

        result.Should().NotBeNullOrEmpty();
        _testOutputHelper.WriteLine(result);
    }

    [Fact]
    public void GetAccessToken_ShouldThrow_WhenEmailIsNull()
    {
        var identityUser = new Frame.Domain.IdentityUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = null,
        };

        var func = () => _sut.GetAccessToken(identityUser);

        func.Should().Throw<ArgumentNullException>();
    }
}
