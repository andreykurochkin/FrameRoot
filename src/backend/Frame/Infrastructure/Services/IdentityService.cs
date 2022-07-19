using FluentValidation;
using Frame.Contracts.V1.Requests;
using Frame.Contracts.V1.Responses;
using Frame.Domain;
using Frame.Infrastructure.Helpers;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services.Base;
using Frame.Infrastructure.Validators.Base;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Frame.Infrastructure.Services;
public class IdentityService : IIdentityService
{
    private readonly IIdentityUserProvider _identityUserProvider;
    private readonly IValidator<UserSignupRequest> _userSignupRequestValidator;
    private readonly IPasswordHashValidator _passwordHashValidator;
    private readonly JwtOptions _jwtOptions;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly TokenValidationParameters _tokenValidationParameters;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IIdentityUserRepository _identityUserRepository;
    private readonly ISecurityTokenProvider _securityTokenProvider;
    private readonly IRefreshTokenProvider _refreshTokenProvider;
    public IdentityService(Validators.Base.IPasswordHashValidator passwordHashValidator,
                           JwtOptions jwtOptions,
                           IDateTimeProvider dateTimeProvider,
                           TokenValidationParameters tokenValidationParameters,
                           IRefreshTokenRepository refreshTokenRepository,
                           IIdentityUserRepository identityUserRepository,
                           ISecurityTokenProvider securityTokenProvider,
                           IRefreshTokenProvider refreshTokenProvider,
                           IValidator<UserSignupRequest> userSignupRequestValidator, 
                           IIdentityUserProvider identityUserProvider)
    {
        _passwordHashValidator = passwordHashValidator;
        _jwtOptions = jwtOptions;
        _dateTimeProvider = dateTimeProvider;
        _tokenValidationParameters = tokenValidationParameters;
        _identityUserRepository = identityUserRepository;
        _securityTokenProvider = securityTokenProvider;
        _refreshTokenProvider = refreshTokenProvider;
        _refreshTokenRepository = refreshTokenRepository;
        _userSignupRequestValidator = userSignupRequestValidator;
        _identityUserProvider = identityUserProvider;
    }

    public async Task<AuthenticationResult> LoginAsync(string? email, string? password)
    {
        var user = await _identityUserRepository.FindByEmailAsync(email);
        if (user is null)
        {
            return new AuthenticationResult
            {
                Errors = new[] { "User doesn`t exist" }
            };
        }
        var identityResult = await _passwordHashValidator.ValidateAsync(user, password);
        if (!identityResult.Succeeded)
        {
            return new AuthenticationResult
            {
                Errors = identityResult.Errors.Select(identityError => identityError.Description)
            };
        }
        return await GenerateAuthenticationResultForUserAsync(user);
    }

    public async Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(Frame.Domain.IdentityUser identityUser)
    {
        var accessToken = _securityTokenProvider.GetSecurityToken(identityUser);
        var refreshToken = _refreshTokenProvider.GetRefreshToken(accessToken, identityUser);

        var jwtToken = new JwtSecurityTokenHandler().WriteToken(accessToken);
        var result = new AuthenticationResult
        {
            Succeded = true,
            AccessToken = jwtToken,
            RefreshToken = refreshToken.Token,
        };
        await _refreshTokenRepository.CreateAsync(refreshToken);
        return result;
    }

    [Authorize]
    public async Task<AuthenticationResult> RefreshTokenAsync(string? token, string? password)
    {
        if (token is null)
        {
            return new AuthenticationResult { Errors = new[] { "Invalid token" } };
        }

        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        if (!jwtSecurityTokenHandler.CanReadToken(token))
        {
            return new AuthenticationResult { Errors = new[] { "Invalid token format" } };
        }

        ClaimsPrincipal? claimsPrincipal = GetClaimsPrincipalFromToken(jwtSecurityTokenHandler, token);
        if (claimsPrincipal == null)
        {
            return new AuthenticationResult { Errors = new[] { "Invalid token" } };
        }

        var userIdFromClaimsPrincipal = claimsPrincipal.Claims.FirstOrDefault(_ => _.Type == "identityUserId");
        if (userIdFromClaimsPrincipal is null)
        {
            return new AuthenticationResult { Errors = new[] { "Claim identityUserId is required" } };
        }

        var jwtExpClaim = claimsPrincipal!.Claims.First(_ => _.Type == JwtRegisteredClaimNames.Exp);
        var expiryDateUnix = long.Parse(jwtExpClaim.Value);
        var expiryDateUnixUtc = new DateTime(year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0, kind: DateTimeKind.Utc).AddSeconds(expiryDateUnix);
        var actualTime = _dateTimeProvider.GetDateTime().ToUniversalTime();
        var tokenExpired = expiryDateUnixUtc < actualTime;
        if (!tokenExpired)
        {
            return new AuthenticationResult { Errors = new[] { "Token hasn`t expired yet" } };
        }

        // todo uncomment
        // get refresh token from persistent via JwtId
        bool persistentIsReady = true;
        RefreshToken? storedRefreshToken = null!;
        if (persistentIsReady)
        {
            var jtiClaim = claimsPrincipal.Claims.Single(_ => _.Type == JwtRegisteredClaimNames.Jti);
            storedRefreshToken = await _refreshTokenRepository.GetRefreshTokenByJwtIdAsync(jtiClaim.Value);
            if (storedRefreshToken is null)
            {
                return new AuthenticationResult { Errors = new[] { "This refresh token doesn`t exit" } };
            }
        }
        else
        {
            //todo delete this
            storedRefreshToken = new RefreshToken();
        }


        var refreshTokenExpired = _dateTimeProvider.GetDateTime().ToUniversalTime() > storedRefreshToken.ExpiryDate;
        if (refreshTokenExpired)
        {
            return new AuthenticationResult { Errors = new[] { "This refresh token has expired" } };
        }

        if (storedRefreshToken.Invalidated)
        {
            return new AuthenticationResult { Errors = new[] { "This refresh token has been invalidated" } };
        }

        if (storedRefreshToken.Used)
        {
            return new AuthenticationResult { Errors = new[] { "This refresh token has been used" } };
        }

        storedRefreshToken.Used = true;
        // todo uncomment
        await _refreshTokenRepository.ReplaceOneAsync(storedRefreshToken);

        var user = await _identityUserRepository.FindByIdAsync(userIdFromClaimsPrincipal.Value);
        return await GenerateAuthenticationResultForUserAsync(user);
    }

    private ClaimsPrincipal? GetClaimsPrincipalFromToken(JwtSecurityTokenHandler jwtSecurityTokenHandler, string? token)
    {
        try
        {
            return JwtSecurityTokenHelper.GetClaimsPrincipalFromToken(jwtSecurityTokenHandler, token, _tokenValidationParameters);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public async Task<AuthenticationResult> SignupAsync(
        string? email,
        string? password,
        string? confirmPassword,
        string? givenName,
        string? familyName)
    {
        var identityUser = await _identityUserRepository.FindByEmailAsync(email);
        if (identityUser is not null)
        {
            return new AuthenticationResult
            {
                ModelFieldErrors = new [] { new ModelEmailFieldError("User with specified email already exists.") },
            };
        }
        var result = Validate(email, password, confirmPassword, givenName, familyName);
        if (!result.IsValid)
        {
            return new AuthenticationResult
            {
                ModelFieldErrors = result.Errors.Select(validationFailure => new ModelFieldError(validationFailure.PropertyName, validationFailure.ErrorMessage))
            };
        }

        identityUser = await _identityUserProvider.GetIdentityUserAsync(email!, password!, familyName!, givenName!);
        await _identityUserRepository.CreateAsync(identityUser);
        return await GenerateAuthenticationResultForUserAsync(identityUser);
    }

    private FluentValidation.Results.ValidationResult Validate(
        string? email,
        string? password,
        string? confirmPassword,
        string? givenName,
        string? familyName)
    {
        var signUpRequest = new UserSignupRequest
        {
            Email = email,
            Password = password,
            ConfirmPassword = confirmPassword,
            GivenName = givenName,
            FamilyName = familyName
        };
        var result = _userSignupRequestValidator.Validate(signUpRequest);
        return result;
    }
}
