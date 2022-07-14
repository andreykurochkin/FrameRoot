using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Repositories.Base;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Frame.Infrastructure.Repositories;
public class RefreshTokenMongoRepository : IRefreshTokenRepository
{
    private readonly IMongoClient _mongoClient;
    private readonly MongoDbOptions _mongoDbOptions;
    private const string MongoCollectionName = "refreshTokens";
    private readonly IMongoCollection<RefreshToken> _refreshTokens;

    public RefreshTokenMongoRepository(
        IMongoClient mongoClient,
        MongoDbOptions mongoDbConfigurationOptions)
    {

        _mongoClient = mongoClient;
        _mongoDbOptions = mongoDbConfigurationOptions;
        var database = _mongoClient.GetDatabase(_mongoDbOptions.DatabaseName);
        _refreshTokens = database.GetCollection<RefreshToken>(MongoCollectionName);
    }
    public async Task<RefreshToken?> GetRefreshTokenByJwtIdAsync(string jwtId) => await _refreshTokens
        .Find(_ => _.JwtId == jwtId)
        .FirstOrDefaultAsync();

    // todo where to include guard close refreshToken is null
    public async Task CreateAsync(RefreshToken? refreshToken) => await _refreshTokens
        .InsertOneAsync(refreshToken!);

    public async Task<ReplaceOneResult> ReplaceOneAsync(RefreshToken? refreshToken)
    {
        var filter = Builders<RefreshToken>.Filter.Eq(_ => _.Token, refreshToken!.Token); 
        var result = await _refreshTokens.ReplaceOneAsync(filter, refreshToken!);
        return result;
    }
}
