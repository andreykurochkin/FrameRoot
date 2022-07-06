namespace Frame.Infrastructure.Providers.Base;
public interface IHashProvider
{
    string GetHash(string password, byte[] salt);
}
