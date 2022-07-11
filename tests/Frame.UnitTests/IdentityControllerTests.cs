using FluentAssertions;
using Frame.Contracts.V1.Requests;
using Frame.Controllers.V1;
using Frame.Domain;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Services.Base;
using Frame.UnitTests.Fixtures;
using Frame.UnitTests.Helpers;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Frame.UnitTests;

[Collection("TokenSpecific Collection")]
public class IdentityControllerTests : IClassFixture<Fixtures.TokenSpecificFixture>
{
    private IdentityController _sut = null!;
    private readonly ITestOutputHelper _testOutputHelper;
    private readonly Mock<IIdentityService> _mockIdentityService = new Mock<IIdentityService>();
    private readonly Mock<IIdentityUserRepository> _mockIdentityUserRepository = new Mock<IIdentityUserRepository>();
    private readonly TokenSpecificFixture _fixture;

    public IdentityControllerTests(ITestOutputHelper testOutputHelper, TokenSpecificFixture fixture)
    {
        _testOutputHelper = testOutputHelper;
        _fixture = fixture;
        _sut = new IdentityController(_mockIdentityService.Object);
    }

    [Fact]
    public async Task Login_ShouldReturnBadRequest_WhenModelStateIsNotValid()
    {
        _sut.ModelState.AddModelError(nameof(ArgumentException), "Bad user login request");

        var result = await _sut.Login(_fixture.UserLoginRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Login_ShouldReturnBadRequest_WhenLoginFailed()
    {
        _mockIdentityService
            .Setup(service => service.LoginAsync(It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(AuthenticationResultHelper.GetFailedOne);

        var result = await _sut.Login(_fixture.UserLoginRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Login_ShouldReturnOk_WhenLoginSucceded()
    {
        _mockIdentityService
            .Setup(service => service.LoginAsync(It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(AuthenticationResultHelper.GetSuccededOne);

        var result = await _sut.Login(_fixture.UserLoginRequest);

        result.Should().BeOfType<OkObjectResult>();
    }

    [Fact]
    public async Task Refresh_ShouldReturnBadReques_WhenDataIsInvalid()
    {
        _mockIdentityService
            .Setup(service => service.RefreshTokenAsync(It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(AuthenticationResultHelper.GetFailedOne);

        var result = await _sut.Refresh(_fixture.RefreshTokenRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Refresh_ShouldReturnOk_WhenDataIsValid()
    {
        _mockIdentityService
            .Setup(service => service.RefreshTokenAsync(It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(AuthenticationResultHelper.GetFailedOne);

        var result = await _sut.Refresh(_fixture.RefreshTokenRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Signup_ShouldReturnBadRequest_WhenModelStateIsNotValid()
    {
        _sut.ModelState.AddModelError(nameof(ArgumentException), "Bad user login request");

        var result = await _sut.Signup(_fixture.UserSignupRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Signup_ShouldReturnBadRequest_WhenDataIsInValid()
    {
        _mockIdentityService
            .Setup(service => service.SignupAsync(It.IsNotNull<string>(), It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(AuthenticationResultHelper.GetFailedOne);

        var result = await _sut.Signup(_fixture.UserSignupRequest);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Signup_ShouldReturnOk_WhenDataIsValid()
    {
        _mockIdentityService
            .Setup(service => service.SignupAsync(It.IsNotNull<string>(), It.IsNotNull<string>(), It.IsNotNull<string>()))
            .ReturnsAsync(AuthenticationResultHelper.GetSuccededOne);

        var result = await _sut.Signup(_fixture.UserSignupRequest);

        result.Should().BeOfType<OkObjectResult>();
    }
}