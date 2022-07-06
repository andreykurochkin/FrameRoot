namespace Frame.Infrastructure.Installers.Base;
public interface IInstaller
{
    void InstallService(IServiceCollection services, IConfiguration configuration);
}
