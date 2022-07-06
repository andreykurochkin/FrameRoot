using Frame.Infrastructure.Installers.Base;
using Microsoft.OpenApi.Models;

namespace Frame.Infrastructure.Installers;
public class SwaggerInstaller : IInstaller
{
    public void InstallService(IServiceCollection services, IConfiguration configuration)
    {
        services.AddSwaggerGen(_ =>
        {
            _.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Tweetbook",
                Version = "v1"
            });

            _.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using bearer scheme",
                Name = "Authorizaiton",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer"
            });
            _.AddSecurityRequirement(new OpenApiSecurityRequirement{
            {
                new OpenApiSecurityScheme{
                    Reference = new OpenApiReference{
                        Id = "Bearer", //The name of the previously defined security scheme.
                        Type = ReferenceType.SecurityScheme
                    }
                },
                new List<string>()
            }
            });
        });
    }
}
