﻿using Frame.Contracts.V1;
using Frame.Contracts.V1.Requests;
using Frame.Contracts.V1.Responses;
using Frame.Infrastructure.Services.Base;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Frame.Controllers.V1;

public class IdentityController : ControllerBase
{
    private readonly IIdentityService _identityService;

    public IdentityController(IIdentityService identityService)
    {
        _identityService = identityService;
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
        var authResponse = await _identityService.LoginAsync(userLoginRequest.Email, userLoginRequest.Password);
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
    
    [Authorize]
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

    [HttpPost(ApiRoutes.Identity.Signup)]
    public async Task<IActionResult> Signup([FromBody] UserSignupRequest userSignupRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new AuthFailedResponse
            {
                Errors = ModelState.Values.SelectMany(_ => _.Errors.Select(error => error.ErrorMessage))
            });
        }
        var authResponse = await _identityService.SignupAsync(
            userSignupRequest.Email,
            userSignupRequest.Password,
            userSignupRequest.ConfirmPassword,
            userSignupRequest.GivenName,
            userSignupRequest.FamilyName);
        if (!authResponse.Succeded)
        {
            var output = new AuthFailedUISpecificResponse
            {
                ModelFieldErrors = authResponse.ModelFieldErrors!.ToList()
            };
            return BadRequest(output.ModelFieldErrors.Select(_ => $"FieldName: {_.FieldName} Error: {_.Error}").ToList());
        }
        return Ok(new AuthSuccessResponse
        {
            Token = authResponse.AccessToken,
            RefreshToken = authResponse.RefreshToken,
        });
    }
}
