using Frame.Domain;

namespace Frame.Infrastructure.Services.Base;
public interface IIdentityService
{
    Task<AuthenticationResult> SignupAsync(string? email, string? password, string? confirmPassword, string? GivenName, string? FamilyName);

    Task<AuthenticationResult> LoginAsync(string? email, string? password);

    Task<AuthenticationResult> RefreshTokenAsync(string? token, string? refreshToken);
}
