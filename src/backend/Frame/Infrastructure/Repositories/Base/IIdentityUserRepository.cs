using Frame.Domain;

namespace Frame.Infrastructure.Repositories.Base;
public interface IIdentityUserRepository
{
    public Task<IdentityUser?> FindByEmailAsync(string? email);

    public Task<IdentityUser>? FindByIdAsync(string? id);

    public Task<List<IdentityUser>> GetAllAsync();

    public Task<IdentityUser> CreateAsync(IdentityUser? identityUser);
}
