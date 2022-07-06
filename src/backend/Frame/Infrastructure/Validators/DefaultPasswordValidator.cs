using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Validators.Base;
using Microsoft.AspNetCore.Identity;
using System.Text;

namespace Frame.Infrastructure.Validators;
public class DefaultPasswordValidator : IPasswordValidator
{
    private readonly IHashProvider _hashProvider;

    public DefaultPasswordValidator(IHashProvider hashProvider)
    {
        _hashProvider = hashProvider;
    }

    public async Task<IdentityResult> ValidateAsync(Domain.IdentityUser user, string password)
    {
        throw new NotImplementedException();
        //var hashFromPersistent = user.Password;
        //var salt = Encoding.ASCII.GetBytes(user.Salt);
        //var hashToValidate = await Task.Run<string>( _hashProvider.GetHash(password, salt));

        //var result = new IdentityResult
    }
}
