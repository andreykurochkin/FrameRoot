using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Frame.Infrastructure.Helpers;

public static class JwtSecurityTokenHelper
{
    public static bool IsJwtTokenWithValidSecurityAlgorithm(SecurityToken securityToken)
    {
        return
            (securityToken is JwtSecurityToken jwtSecurityToken) &&
            jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
    }

    public static ClaimsPrincipal? GetClaimsPrincipalFromToken(string? token, TokenValidationParameters tokenValidationParameters)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        var result = IsJwtTokenWithValidSecurityAlgorithm(validatedToken) ? principal : null;
        return result;
    }
}
