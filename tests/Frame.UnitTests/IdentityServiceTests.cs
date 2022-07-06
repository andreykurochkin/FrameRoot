using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Services.Base;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Frame.UnitTests;
public class IdentityServiceTests
{
    private IdentityService _sut = null!;
    private Mock<IIdentityUserRepository> _mockIdentityUserRepository = new();
    const string Email = "test@test.com";
    const string Password = "pass";

    [Fact]
    public async Task LoginAsync_ShouldReturnFailedAuthenticationResultWithExpectedMessage_WhenUserDoesNotExist()
    {
        const string expectedErrorMessage = "User doesn`t exist";
        IdentityUser nullIdentityUser = null!;
        _mockIdentityUserRepository
            .Setup(identityUserRepository => identityUserRepository.FindByEmailAsync(It.IsNotNull<string>()))
            .ReturnsAsync(nullIdentityUser);
        _sut = new(userService: null!,
                   jwtOptions: null!,
                   dateTimeProvider: null!,
                   httpContextAccessor: null!,
                   tokenValidationParameters: null!,
                   identityUserRepository: _mockIdentityUserRepository.Object);

        var result = await _sut.LoginAsync(Email, Password);

        result.Should().BeOfType<AuthenticationResult>();
        result.Succeded.Should().BeFalse();
        result.Errors.Should().Contain(expectedErrorMessage);
    }
}
