using Frame.Infrastructure.Providers.Base;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Frame.Infrastructure.Providers;
public class DefaultHashProvider : IHashProvider
{
    public string GetHash(string password, byte[] salt)
    {
        var derivedKey = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 32);
        return Convert.ToBase64String(derivedKey);
    }
}
