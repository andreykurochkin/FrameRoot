using Frame.Domain;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using System;
using System.Text;

namespace Frame.UnitTests.Helpers;
public static class IdentityUserHelper
{
    public static IdentityUser GetOne(string email = "test@test.com", string password = "password")
    {
        var salt = new DefaultSaltProvider().GetSalt();
        var saltAsBytes = Encoding.ASCII.GetBytes(salt);
        var hashedPassword = new DefaultHashProvider().GetHashAsync(password, saltAsBytes).GetAwaiter().GetResult();
        return new IdentityUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = email,
            Password = hashedPassword,
            Salt = salt,
        };
    }

    public static IdentityUser? GetNull() => null;
}
