using Frame.Infrastructure.Options;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using System;

namespace Frame.IntegrationTests.Fixtures;
public class MongoDbFixture : IDisposable
{
    public MongoDbOptions MongoDbOptions { get; set; }
    public MongoClient MongoClient { get; init; }

    private void InitializeMongoDbOptions()
    {
        var configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
        MongoDbOptions = configuration.GetSection("MongoDbOptions").Get<MongoDbOptions>();
        var dbName = $"test_db_{Guid.NewGuid()}";
        MongoDbOptions.DatabaseName = dbName;
    }

    public MongoDbFixture()
    {
        InitializeMongoDbOptions();
        ArgumentNullException.ThrowIfNull(MongoDbOptions!.ConnectionString);
        MongoClient = new MongoClient(MongoDbOptions.ConnectionString);
    }

    public void Dispose()
    {
        MongoClient.DropDatabase(MongoDbOptions.DatabaseName);
    }
}
