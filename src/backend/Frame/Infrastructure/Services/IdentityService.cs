using Frame.Domain;
using Frame.Infrastructure.Helpers;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services.Base;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Frame.Infrastructure.Services;
public class IdentityService : IIdentityService
{
    private readonly Validators.Base.IPasswordValidator _passwordValidator;
    private readonly JwtOptions _jwtOptions;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly TokenValidationParameters _tokenValidationParameters;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IIdentityUserRepository _identityUserRepository;
    private readonly ISecurityTokenProvider _securityTokenProvider;
    private readonly IRefreshTokenProvider _refreshTokenProvider;
    public IdentityService(Validators.Base.IPasswordValidator passwordValidator,
                           JwtOptions jwtOptions,
                           IDateTimeProvider dateTimeProvider,
                           TokenValidationParameters tokenValidationParameters,
                           IRefreshTokenRepository refreshTokenRepository,
                           IIdentityUserRepository identityUserRepository,
                           ISecurityTokenProvider securityTokenProvider,
                           IRefreshTokenProvider refreshTokenProvider)
    {
        _passwordValidator = passwordValidator;
        _jwtOptions = jwtOptions;
        _dateTimeProvider = dateTimeProvider;
        _tokenValidationParameters = tokenValidationParameters;
        _identityUserRepository = identityUserRepository;
        _securityTokenProvider = securityTokenProvider;
        _refreshTokenProvider = refreshTokenProvider;
        _refreshTokenRepository = refreshTokenRepository;
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
        var identityResult = await _passwordValidator.ValidateAsync(user, password);
        if (!identityResult.Succeeded)
        {
            return new AuthenticationResult
            {
                Errors = identityResult.Errors.Select(identityError => identityError.Description)
            };
        }
        return await GenerateAuthenticationResultForUserAsync(user);
    }

    public Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(Frame.Domain.IdentityUser identityUser)
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
        return Task.FromResult(result);
    }

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
        await _refreshTokenRepository.SaveChangesAsync(storedRefreshToken);

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

    public Task<AuthenticationResult> SignupAsync(string? email, string? password, string? confirmPassword)
    {
        throw new NotImplementedException();
    }
}
