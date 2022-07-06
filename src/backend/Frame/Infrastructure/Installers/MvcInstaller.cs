using Frame.Infrastructure.Installers.Base;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Services.Base;
using Frame.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Frame.Infrastructure.Validators.Base;
using Frame.Infrastructure.Validators;

namespace Frame.Infrastructure.Installers;
public class MvcInstaller : IInstaller
{
    public void InstallService(IServiceCollection services, IConfiguration configuration)
    {
        var jwtOptions = configuration.GetSection("JwtOptions").Get<JwtOptions>();
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtOptions.Secret)),
            ValidateIssuer = false,
            ValidateAudience = false,
            RequireExpirationTime = false,
            ValidateLifetime = true,
        };
        services.AddSingleton(tokenValidationParameters);
        services.AddSingleton(jwtOptions);

        AuthenticationBuilder authenticationBuilder = services.AddAuthentication(authenticationOptions =>
        {
            authenticationOptions.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            authenticationOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            authenticationOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            authenticationOptions.DefaultForbidScheme = JwtBearerDefaults.AuthenticationScheme;
        });
        authenticationBuilder.AddJwtBearer(jwtBearerOptions =>
        {
            jwtBearerOptions.SaveToken = true;
            jwtBearerOptions.TokenValidationParameters = tokenValidationParameters;
        });

        services.AddSingleton<IDateTimeProvider,DateTimeNowProvider>();
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddSingleton<ISaltProvider, DefaultSaltProvider>();
        services.AddSingleton<IHashProvider, DefaultHashProvider>();
        services.AddSingleton<IPasswordValidator, DefaultPasswordValidator>();
        services.AddSingleton<ISecurityTokenProvider, DefaultSecurityTokenProvider>();
        services.AddSingleton<IRefreshTokenProvider, DefaultRefreshTokenProvider>();

        services.AddControllers();
    }
}
