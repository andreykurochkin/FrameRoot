using FluentAssertions;
using Frame.Infrastructure.Providers;
using Xunit;

namespace Frame.UnitTests;
public class DefaultSaltProviderTests
{
    private readonly DefaultSaltProvider _sut = new DefaultSaltProvider();
    
    [Fact]
    public void GetSalt_ShouldGenerateNotNullSalt()
    {
        var result = _sut.GetSalt();

        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetSalt_ShouldGenerateRandomValues()
    { 
        var result1 = _sut.GetSalt();
        var result2 = _sut.GetSalt();

        result1.Should().NotBe(result2);
    }
}
