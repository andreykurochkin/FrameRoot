using FluentAssertions;
using Frame.Contracts.V1.Requests;
using Frame.Controllers.V1;
using Frame.Domain;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Services.Base;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;
public class IdentityControllerTests
{
    private IdentityController _sut = null!;
    private readonly ITestOutputHelper _testOutputHelper;
    const string Email = "test@test.com";
    const string Password = "pass";
    private readonly UserLoginRequest _userLoginRequest = new UserLoginRequest { Email = Email, Password = Password };
    private readonly Mock<IIdentityService> _moqIdentityService = new Mock<IIdentityService>();

    public IdentityControllerTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public async Task Login_ShouldReturnBadRequest_WhenModelStateIsNotValid()
    {
        _sut = new IdentityController(identityService: null!, identityUserRepository: null!);
        _sut.ModelState.AddModelError(nameof(ArgumentException), "Bad user login request");

        var result = await _sut.Login(_userLoginRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Login_ShouldReturnBadRequest_WhenLoginFailed()
    { 
        _moqIdentityService
            .Setup(identityService => identityService.LoginAsync(It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(new AuthenticationResult { Succeded = false });
        _sut = new IdentityController(identityService: _moqIdentityService.Object, identityUserRepository: null!);

        var result = await _sut.Login(_userLoginRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Login_ShouldReturnOk_WhenLoginSucceded()
    {
        _moqIdentityService
            .Setup(identityService => identityService.LoginAsync(It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(new AuthenticationResult { Succeded = true });
        _sut = new IdentityController(identityService: _moqIdentityService.Object, identityUserRepository: null!);

        var result = await _sut.Login(_userLoginRequest);

        result.Should().BeOfType<OkObjectResult>();
    }

    [Fact]
    public async Task RefreshToken_ShouldReturnBadRequest_WhenDataIsNotValid()
    {

    }
}