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
        var hashFromPersistent = user.Password;
        var salt = Encoding.ASCII.GetBytes(user.Salt);
        var hashToValidate = await _hashProvider.GetHashAsync(password, salt);
        var validated = hashFromPersistent == hashToValidate;
        return validated
            ? IdentityResult.Success 
            : IdentityResult.Failed(new[]
            {
                new IdentityError
                {
                    Code = string.Empty,
                    Description = "Bad login/password pair"
                }
            });
    }
}
