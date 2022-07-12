using Frame.Domain;
using Frame.Infrastructure.Providers.Base;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Frame.Infrastructure.Providers;

public class DefaultIdentityUserProvider : IIdentityUserProvider
{
    private readonly ISaltProvider _saltProvider;
    private readonly IHashProvider _hashProvider;

    public DefaultIdentityUserProvider(ISaltProvider saltProvider, IHashProvider hashProvider)
    {
        _saltProvider = saltProvider;
        _hashProvider = hashProvider;
    }

    public async Task<IdentityUser> GetIdentityUserAsync(string email, string password, string familyName, string givenName)
    {
        var salt = _saltProvider.GetSalt();
        var newUserId = Guid.NewGuid().ToString();
        var claims = CreateClaims(email, newUserId);
        var identityUser = new IdentityUser
        {
            Id = newUserId,
            Claims = claims,
            Email = email,
            Salt = salt,
            Password = await _hashProvider.GetHashAsync(password, Encoding.ASCII.GetBytes(salt)),
            FamilyName = familyName,
            GivenName = givenName
        };
        return identityUser;
    }

    private IEnumerable<Claim> CreateClaims(string email, string userId)
    {
        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, email),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim("identityUserId", userId),
        };
        return claims;
    }
}
