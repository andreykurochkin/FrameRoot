using Frame.Infrastructure.Providers.Base;
using System.Security.Cryptography;

namespace Frame.Infrastructure.Providers;
public class DefaultSaltProvider : ISaltProvider
{
    private const int count = 32;
    public string GetSalt() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(count));
}
