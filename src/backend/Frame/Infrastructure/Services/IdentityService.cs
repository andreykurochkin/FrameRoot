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
    //private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IIdentityUserRepository _identityUserRepository;
    private readonly ISecurityTokenProvider _securityTokenProvider;
    private readonly IRefreshTokenProvider _refreshTokenProvider;
    public IdentityService(Validators.Base.IPasswordValidator passwordValidator,
                           JwtOptions jwtOptions,
                           IDateTimeProvider dateTimeProvider,
                           TokenValidationParameters tokenValidationParameters/*,
                           IRefreshTokenRepository refreshTokenRepository*/,
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
        //_refreshTokenRepository = refreshTokenRepository;
    }

    public async Task<AuthenticationResult> LoginAsync(string email, string password)
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

    private async Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(Frame.Domain.IdentityUser identityUser)
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
        return result;
    }

    public async Task<AuthenticationResult> RefreshTokenAsync(string? token, string? password)
    {
        var claimsPrincipal = JwtSecurityTokenHelper.GetClaimsPrincipalFromToken(token, _tokenValidationParameters);
        if (claimsPrincipal is null)
        {
            return new AuthenticationResult { Errors = new[] { "Invalid token" } };
        }

        var jwtExpClaim = claimsPrincipal.Claims.First(_ => _.Type == JwtRegisteredClaimNames.Exp);
        var expiryDateUnix = long.Parse(jwtExpClaim.Value);
        var expiryDateUnixUtc = new DateTime(year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0, kind: DateTimeKind.Utc).AddSeconds(expiryDateUnix);
        var tokenExpired = expiryDateUnixUtc > _dateTimeProvider.GetDateTime().ToUniversalTime();
        if (!tokenExpired)
        {
            if (claimsPrincipal is null)
            {
                return new AuthenticationResult { Errors = new[] { "Token hasn`t expired yet" } };
            }
        }

        // todo uncomment
        // get refresh token from persistent via JwtId
        //var jtiClaim = claimsPrincipal.Claims.Single(_ => _.Type == JwtRegisteredClaimNames.Jti);
        //var storedRefreshToken = await _refreshTokenRepository.GetRefreshTokenByJwtIdAsync(jtiClaim.Value);
        //if (storedRefreshToken is null)
        //{
        //    return new AuthenticationResult { Errors = new[] { "This refresh token doesn`t exit" } };
        //}

        // todo delete this
        var storedRefreshToken = new RefreshToken();

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
        //await _refreshTokenRepository.SaveChangesAsync(storedRefreshToken);

        var userIdFromClaimsPrincipal = claimsPrincipal.Claims.Single(_ => _.Type == "id");
        var user = await _identityUserRepository.FindByIdAsync(userIdFromClaimsPrincipal.Value);
        return await GenerateAuthenticationResultForUserAsync(user);
        // return call to GenerateAuthenticationResultForUserAsync(via found user)

        throw new NotImplementedException();
    }

    public Task<AuthenticationResult> RegisterUserAsync(string userName, string password)
    {
        throw new NotImplementedException();
    }
}
