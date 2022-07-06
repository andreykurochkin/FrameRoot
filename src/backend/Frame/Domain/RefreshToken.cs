using Microsoft.AspNetCore.Identity;

namespace Frame.Domain;
public class RefreshToken
{
    public string? Token { get; set; } = null!;
    public string? JwtId { get; set; } = null!;
    public DateTime? CreationDate { get; set; }
    public DateTime? ExpiryDate { get; set; }
    public bool Used { get; set; }
    public bool Invalidated { get; set; }
    public IdentityUser<Guid>? User { get; set; }
    public string? UserId { get; set; }
}
