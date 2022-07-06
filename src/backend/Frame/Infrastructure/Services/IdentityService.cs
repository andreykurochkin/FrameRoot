using Frame.Domain;
using Frame.Infrastructure.Helpers;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Services.Base;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Frame.Infrastructure.Services;
public class IdentityService : IIdentityService
{
    private readonly IUserService _userService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly JwtOptions _jwtOptions;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly TokenValidationParameters _tokenValidationParameters;
    //private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IIdentityUserRepository _identityUserRepository;
    public IdentityService(IUserService userService,
                           JwtOptions jwtOptions,
                           IDateTimeProvider dateTimeProvider,
                           IHttpContextAccessor httpContextAccessor,
                           TokenValidationParameters tokenValidationParameters/*,
                           IRefreshTokenRepository refreshTokenRepository*/
                                                                           , IIdentityUserRepository identityUserRepository)
    {
        _userService = userService;
        _jwtOptions = jwtOptions;
        _dateTimeProvider = dateTimeProvider;
        _httpContextAccessor = httpContextAccessor;
        _tokenValidationParameters = tokenValidationParameters;
        _identityUserRepository = identityUserRepository;
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
        var passwordIsValid = await _userService.CheckPasswordAsync(user, password);
        if (!passwordIsValid)
        {
            return new AuthenticationResult
            {
                Errors = new[] { "Bad login/password pair" }
            };
        }
        return await GenerateAuthenticationResultForUserAsync(user);
    }

    private Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(Frame.Domain.IdentityUser identityUser)
    {
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, identityUser.Email),
            new Claim(JwtRegisteredClaimNames.Email, identityUser.Email),
            new Claim("identityUserId", identityUser.Id.ToString()),
        };
        var userClaims = _httpContextAccessor.HttpContext?.User.Claims ?? Enumerable.Empty<Claim>();
        claims.AddRange(userClaims);

        var key = Encoding.ASCII.GetBytes(_jwtOptions.Secret);
        var symmetricSecurityKey = new SymmetricSecurityKey(key);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = _dateTimeProvider.GetDateTime().Add(_jwtOptions.TokenLifeTime),
            SigningCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature),
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var accessToken = tokenHandler.CreateToken(tokenDescriptor);
        var refreshToken = new RefreshToken
        {
            Token = Guid.NewGuid().ToString(),
            JwtId = accessToken.Id,
            UserId = identityUser.Id.ToString(),
            CreationDate = _dateTimeProvider.GetDateTime(),
            ExpiryDate = _dateTimeProvider.GetDateTime().AddMonths(6),
        };

        var result = new AuthenticationResult
        {
            Succeded = true,
            Token = tokenHandler.WriteToken(accessToken),
            RefreshToken = refreshToken.Token,
        };
        return Task.FromResult(result);
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
