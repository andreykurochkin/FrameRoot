using FluentAssertions;
using Frame.Infrastructure.Helpers;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;
public class DateTimeOperationsHelperTests
{
    private readonly InstanceWrapper _sut;
    private readonly ITestOutputHelper _testOutputHelper;
    internal class InstanceWrapper
    {
        public DateTime GetExpiryUnixUtcDateTimeUtc(Claim jwtExpClaim) => DateTimeOperationsHelper.GetExpiryUnixDateTimeUtc(jwtExpClaim);
    }

    public DateTimeOperationsHelperTests(ITestOutputHelper testOutputHelper)
    {
        _sut = new InstanceWrapper();
        _testOutputHelper = testOutputHelper;
    }

    [Theory]
    [InlineData("0", "1/1/1970 12:00:00 AM")]
    [InlineData("1", "1/1/1970 12:00:01 AM")]
    [InlineData("10", "1/1/1970 12:00:10 AM")]
    public void GetUnixNow_ShouldReturn_ExpectedValue(string claimValue, string expectedDate)
    {
        var jwtClaim = new Claim(JwtRegisteredClaimNames.Exp, claimValue);
        var expectedResult = Convert.ToDateTime(expectedDate);

        var result = _sut.GetExpiryUnixUtcDateTimeUtc(jwtClaim);
        
        result.Should().Be(expectedResult);
        _testOutputHelper.WriteLine(result.ToString());
    }

    [Fact]
    public void CompareDates_ShouldReturn_ExpectedValue()
    {
        var jwtClaim = new Claim(JwtRegisteredClaimNames.Exp, "1");
        var now = DateTime.UtcNow;

        var result = _sut.GetExpiryUnixUtcDateTimeUtc(jwtClaim);

        result.Should().BeBefore(now);
    }
}
