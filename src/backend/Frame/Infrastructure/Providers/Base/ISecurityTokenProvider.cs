using Microsoft.IdentityModel.Tokens;

namespace Frame.Infrastructure.Providers.Base;
public interface ISecurityTokenProvider
{
    public SecurityToken GetSecurityToken(Frame.Domain.IdentityUser identityUser);
}
