using FluentAssertions;
using Frame.Contracts.V1.Requests;
using Frame.Controllers.V1;
using Frame.Domain;
using Frame.Infrastructure.Services;
using Frame.Infrastructure.Services.Base;
using Frame.UnitTests.Fixtures;
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
    private readonly Mock<IIdentityService> _moqIdentityService = new Mock<IIdentityService>();
    private readonly TokenSpecificFixture _fixture;
    private readonly UserLoginRequest _userLoginRequest;

    public IdentityControllerTests(ITestOutputHelper testOutputHelper, TokenSpecificFixture fixture) 
    {
        _testOutputHelper = testOutputHelper;
        _fixture = fixture;
        _userLoginRequest = new UserLoginRequest 
        { 
            Email = TokenSpecificFixture.Email, 
            Password = TokenSpecificFixture.Password 
        };
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
}