using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Frame.IntegrationTests;
public class PasswordHasherTests
{
    private readonly PasswordHasher<IdentityUser<Guid>> _sut = new();
    private readonly Guid _mainGuid = Guid.NewGuid();
    private readonly Guid _additionalGuid = Guid.NewGuid();
    private readonly IdentityUser<Guid> _user;
    private readonly ITestOutputHelper _testOutputHelper;

    public PasswordHasherTests(ITestOutputHelper testOutputHelper)
    {
        _user = new IdentityUser<Guid>()
        {
            Id = _mainGuid,
        };
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void VerifyHashedPassword_ShouldReturnSuccess_WhenDataIsValid()
    {
        var hashedPassword = _sut.HashPassword(user: _user, password: _mainGuid.ToString());
        _user.PasswordHash = hashedPassword;

        var result = _sut.VerifyHashedPassword(user: _user,
                                            hashedPassword: _user.PasswordHash,
                                            providedPassword: _mainGuid.ToString());
        
        result.Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void VerifyHashedPassword_ShouldReturnFail_WhenDataIsInValid()
    {
        var hashedPassword = _sut.HashPassword(user: _user, password: _mainGuid.ToString());
        _user.PasswordHash = hashedPassword;

        var result = _sut.VerifyHashedPassword(user: _user,
                                            hashedPassword: _user.PasswordHash,
                                            providedPassword: _additionalGuid.ToString());

        result.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void HashPassword_ShouldReturnSameResult_WhenInputDataRemainsTheSame()
    {

        var firstHashedPassword = _sut.HashPassword(user: _user, password: _mainGuid.ToString());
        var secondHashedPassword = _sut.HashPassword(user: _user, password: _mainGuid.ToString());

        _testOutputHelper.WriteLine(firstHashedPassword);
        _testOutputHelper.WriteLine(secondHashedPassword);
        firstHashedPassword.Should().Be(secondHashedPassword);

        //Object.ReferenceEquals(_user, _user).Should().BeTrue();
    }
}
