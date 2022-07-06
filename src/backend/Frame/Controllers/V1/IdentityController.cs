using Frame.Contracts.V1;
using Frame.Contracts.V1.Requests;
using Frame.Contracts.V1.Responses;
using Frame.Domain;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services.Base;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Frame.Controllers.V1;

public class IdentityController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly IIdentityUserRepository _identityUserRepository;

    public IdentityController(IIdentityService identityService,
        IIdentityUserRepository identityUserRepository)
    {
        _identityService = identityService;
        _identityUserRepository = identityUserRepository;
    }

    [HttpPost(ApiRoutes.Identity.Registration)]
    public IActionResult Register()
    {
        return Ok("test1");
    }

    [HttpGet(ApiRoutes.Identity.Test)]
    public async Task<IActionResult> Test()
    {
        var user = new IdentityUser
        {
            //Id = Guid.NewGuid().ToString(),
            Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Typ, Guid.NewGuid().ToString())
            },
            Email = "Test@test.com",
            FamilyName = "Mercury",
            GivenName = "Freddie",
            Salt = "salt",
            Password = "pass",
        };
        await _identityUserRepository.CreateAsync(user);
        return Ok();
        //return Ok(await _identityUserRepository.GetAllAsync());
    }

    [HttpPost(ApiRoutes.Identity.Login)]
    public async Task<IActionResult> Login([FromBody] UserLoginRequest userLoginRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new AuthFailedResponse
            {
                Errors = ModelState.Values.SelectMany(modelStateEntry => modelStateEntry.Errors.Select(modelError => modelError.ErrorMessage))
            });
        }
        // todo check nullable string
        var authResponse = await _identityService.LoginAsync(userLoginRequest.Email!, userLoginRequest.Password!);
        if (!authResponse.Succeded)
        {
            return BadRequest(new AuthFailedResponse
            {
                Errors = authResponse.Errors
            });
        }
        return Ok(new AuthSuccessResponse
        {
            Token = authResponse.AccessToken,
            RefreshToken = authResponse.RefreshToken,
        });
    }

    [HttpPost(ApiRoutes.Identity.Refresh)]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest refreshTokenRequest)
    {
        var authResponse = await _identityService.RefreshTokenAsync(refreshTokenRequest.Token, refreshTokenRequest.RefreshToken);
        if (!authResponse.Succeded)
        {
            return BadRequest(new AuthFailedResponse 
            { 
                Errors = authResponse.Errors
            });
        }
        return Ok(new AuthSuccessResponse
        {
            Token = authResponse.AccessToken,
            RefreshToken = authResponse.RefreshToken
        });
    }
}
