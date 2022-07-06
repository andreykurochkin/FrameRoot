using Frame.Infrastructure.Installers.Base;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.IdGenerators;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson;
using Frame.Infrastructure.Options;
using MongoDB.Driver;
using Frame.Infrastructure.Repositories.Base;
using Frame.Infrastructure.Repositories;

namespace Frame.Infrastructure.Installers;
public class MongoDbInstaller : IInstaller
{
    public void InstallService(IServiceCollection services, IConfiguration configuration)
    {
        var pack = new ConventionPack();
        pack.Add(new CamelCaseElementNameConvention());
        ConventionRegistry.Register("camelCase", pack, t => true);

        BsonClassMap.RegisterClassMap<Frame.Domain.IdentityUser>(classMap =>
        {
            classMap.AutoMap();
            classMap.MapIdMember(member => member.Id)
                .SetIdGenerator(StringObjectIdGenerator.Instance)
                .SetSerializer(new StringSerializer(BsonType.ObjectId));
        });
        
        var mongoDbOptions = configuration.GetSection("MongoDbOptions").Get<MongoDbOptions>();
        services.AddSingleton(mongoDbOptions);
        services.AddSingleton<IMongoClient>(new MongoClient());
        services.AddScoped<IIdentityUserRepository, IdentityUserMongoRepository>();
    }
}
