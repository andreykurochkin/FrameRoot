using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Frame.Infrastructure.Providers;

public class DefaultSecurityTokenProvider : ISecurityTokenProvider
{
    private readonly JwtOptions _jwtOptions;
    private readonly IDateTimeProvider _dateTimeProvider;

    public DefaultSecurityTokenProvider(
        JwtOptions jwtOptions,
        IDateTimeProvider dateTimeProvider)
    {
        _jwtOptions = jwtOptions;
        _dateTimeProvider = dateTimeProvider;
    }

    private static SigningCredentials CreateSigningCredentials(byte[] key)
    {
        var symmetricSecurityKey = new SymmetricSecurityKey(key);
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);
        return signingCredentials;
    }

    public static SecurityToken GetSecurityToken(IEnumerable<Claim> claims, DateTime expires, byte[] key)
    {
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expires.ToUniversalTime(),
            SigningCredentials = CreateSigningCredentials(key),
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var result = tokenHandler.CreateToken(tokenDescriptor);
            return result;
        }
        catch (Exception)
        {
            throw;
        }
    }

    public IEnumerable<Claim> GetClaims(Frame.Domain.IdentityUser identityUser)
    {
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, identityUser.Email),
            new Claim(JwtRegisteredClaimNames.Email, identityUser.Email),
            new Claim("identityUserId", identityUser.Id.ToString()),
        };
        var userClaims = identityUser.Claims?.ToList() ?? Enumerable.Empty<Claim>();
        claims.AddRange(userClaims);
        return claims;
    }

    private DateTime GetExpires(TimeSpan tokenLifeTime) => _dateTimeProvider.GetDateTime().ToUniversalTime().Add(tokenLifeTime);

    public SecurityToken GetSecurityToken(Frame.Domain.IdentityUser identityUser)
    {
        var claims = GetClaims(identityUser);
        var expires = GetExpires(_jwtOptions.TokenLifeTime);
        var key = Encoding.ASCII.GetBytes(_jwtOptions.Secret);
        var result = GetSecurityToken(claims, expires, key);
        return result;
    }
}