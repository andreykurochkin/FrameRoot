using Microsoft.AspNetCore.Identity;

namespace Frame.Infrastructure.Validators.Base;
public interface IPasswordValidator
{
    Task<IdentityResult> ValidateAsync(Frame.Domain.IdentityUser user, string? password);
}
