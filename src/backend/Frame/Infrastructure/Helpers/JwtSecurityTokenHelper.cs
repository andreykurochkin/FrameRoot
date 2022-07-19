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

    public static ClaimsPrincipal? GetClaimsPrincipalFromToken(
        JwtSecurityTokenHandler jwtSecurityTokenHandler,
        string? token,
        TokenValidationParameters tokenValidationParameters)
    {
        var principal = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        return IsJwtTokenWithValidSecurityAlgorithm(validatedToken) 
            ? principal 
            : null;
    }
}
