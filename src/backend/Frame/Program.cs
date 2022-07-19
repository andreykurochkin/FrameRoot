using Frame.Infrastructure.Installers;
using Frame.Infrastructure.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.InstallServicesInAssembly(builder.Configuration);

var app = builder.Build();

var swaggerOptions = app.Configuration.GetSection("SwaggerOptions").Get<SwaggerOptions>();
app.UseSwagger(options => options.RouteTemplate = swaggerOptions.JsonRoute);
app.UseSwaggerUI(options => options.SwaggerEndpoint(swaggerOptions.UIEndPoint, swaggerOptions.Description));

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
