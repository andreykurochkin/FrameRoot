namespace Frame.Infrastructure.Providers.Base;
public interface IJwtProvider
{
    public string GetAccessToken(Frame.Domain.IdentityUser identityUser);
}
