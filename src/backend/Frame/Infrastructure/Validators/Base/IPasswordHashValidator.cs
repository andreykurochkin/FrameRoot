using Microsoft.AspNetCore.Identity;

namespace Frame.Infrastructure.Validators.Base;
public interface IPasswordHashValidator
{
    Task<IdentityResult> ValidateAsync(Frame.Domain.IdentityUser user, string? password);
}
