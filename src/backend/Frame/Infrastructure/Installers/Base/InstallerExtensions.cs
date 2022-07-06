using Frame.Infrastructure.Installers.Base;

namespace Frame.Infrastructure.Installers;

public static class InstallerExtensions
{
    public static void InstallServicesInAssembly(this IServiceCollection services, IConfiguration configuration)
    {
        var installers = typeof(Program).Assembly.ExportedTypes
            .Where(type => type.IsAssignableTo(typeof(IInstaller)) && !type.IsInterface && !type.IsAbstract)
            .Select(Activator.CreateInstance)
            .Cast<IInstaller>();
        installers.ToList().ForEach(installer => installer.InstallService(services, configuration));
    }
}