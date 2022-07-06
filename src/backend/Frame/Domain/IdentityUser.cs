using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Security.Claims;

namespace Frame.Domain;
public class IdentityUser
{
    public string Id { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string PasswordSalt { get; set; } = null!;
    public string GivenName { get; set; } = null!;
    public string FamilyName { get; set; } = null!;
    public IEnumerable<Claim>? Claims { get; set; }
}
