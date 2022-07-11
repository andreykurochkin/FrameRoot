using Frame.Domain;

namespace Frame.Infrastructure.Services.Base;
public interface IIdentityService
{
    Task<AuthenticationResult> RegisterUserAsync(string email, string password);

    Task<AuthenticationResult> LoginAsync(string? email, string? password);

    Task<AuthenticationResult> RefreshTokenAsync(string? token, string? refreshToken);


}
