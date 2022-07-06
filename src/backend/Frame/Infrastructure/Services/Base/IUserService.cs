
using Frame.Domain;

namespace Frame.Infrastructure.Services.Base;
// remove interface
public interface IUserService
{
    // move to helper class
    public Task<bool> CheckPasswordAsync(IdentityUser user, string password);
}
