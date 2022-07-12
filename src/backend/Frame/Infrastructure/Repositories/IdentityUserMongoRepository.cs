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
    public async Task<IdentityUser?> FindByEmailAsync(string? email) => await _identityUsers
        .Find(_ => _.Email == email)
        .FirstOrDefaultAsync();

    public async Task<IdentityUser?> FindByIdAsync(string? id) => await _identityUsers
        .Find(_ => _.Id == id)
        .FirstOrDefaultAsync();

    public async Task<List<IdentityUser>> GetAllAsync() => await _identityUsers
        .Find(_ => true)
        .ToListAsync();

    public async Task CreateAsync(IdentityUser? identityUser) => await _identityUsers.InsertOneAsync(identityUser);
}
