using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Frame.Infrastructure.Providers;
public class DefaultJwtProvider : IJwtProvider
{
    private readonly JwtOptions _jwtOptions;
    private readonly IDateTimeProvider _dateTimeProvider;

    public DefaultJwtProvider(
        JwtOptions jwtOptions,
        IDateTimeProvider dateTimeProvider)
    {
        _jwtOptions = jwtOptions;
        _dateTimeProvider = dateTimeProvider;
    }

    private SigningCredentials CreateSigningCredentials(byte[] key)
    {
        var symmetricSecurityKey = new SymmetricSecurityKey(key);
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);
        return signingCredentials;
    }

    private string GetAccessToken(IEnumerable<Claim> claims, DateTime expires, byte[] key)
    {
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            SigningCredentials = CreateSigningCredentials(key),
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var accessToken = tokenHandler.CreateToken(tokenDescriptor);
        var result = tokenHandler.WriteToken(accessToken);
        return result;
    }

    private IEnumerable<Claim> GetClaims(Frame.Domain.IdentityUser identityUser)
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

    public string GetAccessToken(Frame.Domain.IdentityUser identityUser)
    {
        var claims = GetClaims(identityUser);
        var expires = GetExpires(_jwtOptions.TokenLifeTime);
        var key = Encoding.ASCII.GetBytes(_jwtOptions.Secret);
        var result = GetAccessToken(claims, expires, key);
        return result;
    }
}