namespace Frame.Infrastructure.Providers.Base;
public interface IHashProvider
{
    Task<string> GetHashAsync(string password, byte[] salt);
}
