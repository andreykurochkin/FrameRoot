using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Repositories.Base;
using MongoDB.Driver;

namespace Frame.Infrastructure.Repositories;
public class IdentityUserMongoRepository : IIdentityUserRepository
{
    private readonly IMongoClient _mongoClient;
    private readonly MongoDbOptions _mongoDbOptions;
    private const string MongoCollectionName = "identityUsers";
    private readonly IMongoCollection<IdentityUser> _identityUsers;

    public IdentityUserMongoRepository(
        IMongoClient mongoClient,
        MongoDbOptions mongoDbConfigurationOptions)
    {
        _mongoClient = mongoClient;
        _mongoDbOptions = mongoDbConfigurationOptions;
        var database = _mongoClient.GetDatabase(_mongoDbOptions.DatabaseName);
        _identityUsers = database.GetCollection<IdentityUser>(MongoCollectionName);
    }
    public Task<IdentityUser?> FindByEmailAsync(string? email)
    {
        throw new NotImplementedException();
    }

    public Task<IdentityUser>? FindByIdAsync(string? id)
    {
        throw new NotImplementedException();
    }

    public async Task<List<IdentityUser>> GetAllAsync()
    {
        return await _identityUsers.Find(_ => true).ToListAsync();
    }

    public async Task<IdentityUser> CreateAsync(IdentityUser? identityUser)
    {
        await _identityUsers.InsertOneAsync(identityUser!);
        return identityUser;
    }
}
