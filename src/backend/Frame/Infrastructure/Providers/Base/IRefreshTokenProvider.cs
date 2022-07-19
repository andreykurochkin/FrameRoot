using Frame.Domain;
using Microsoft.IdentityModel.Tokens;

namespace Frame.Infrastructure.Providers.Base;
public interface IRefreshTokenProvider
{
    RefreshToken GetRefreshToken(SecurityToken accessToken, IdentityUser identityUser);
}
