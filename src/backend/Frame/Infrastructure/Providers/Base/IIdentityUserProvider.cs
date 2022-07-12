using Frame.Domain;

namespace Frame.Infrastructure.Providers.Base;

public interface IIdentityUserProvider
{
    Task<IdentityUser> GetIdentityUserAsync(string email, string password, string familyName, string givenName);
}
