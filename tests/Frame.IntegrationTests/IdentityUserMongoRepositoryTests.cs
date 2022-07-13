using FluentAssertions;
using Frame.Domain;
using Frame.Infrastructure.Repositories;
using Frame.IntegrationTests.Fixtures;
using Frame.UnitTests.Helpers;
using System;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Xunit;

namespace Frame.IntegrationTests;

//public class RefreshTokenMongoRepositoryTests : IClassFixture<MongoDbFixture>
//{
//    private readonly MongoDbFixture _fixture;
//    private readonly RefreshTokenMongoRepository _sut;
//    public RefreshTokenMongoRepositoryTests(MongoDbFixture fixture)
//    {
//        _fixture = fixture;
//        _sut = new RefreshTokenMongoRepository();
//    }
//}

public class IdentityUserMongoRepositoryTests : IClassFixture<MongoDbFixture>
{
    private readonly MongoDbFixture _fixture;
    private IdentityUserMongoRepository _sut;
    private readonly IdentityUser _identityUser;
    public IdentityUserMongoRepositoryTests(MongoDbFixture fixture)
    {
        _fixture = fixture;
        _sut = new IdentityUserMongoRepository(
            mongoClient: _fixture.MongoClient,
            mongoDbConfigurationOptions: _fixture.MongoDbOptions);
        _identityUser = IdentityUserHelper.GetOne();
    }

    private async Task CreateIdentityUserInPersistent()
    {
        await _sut.CreateAsync(_identityUser);
        var storedUser = await _sut.FindByEmailAsync(_identityUser.Email);
    }

    [Fact]
    public async void FindByEmailAsync_ShouldReturnNull_WhenIsNotStored()
    {
        var uniqueUser = CreateIdentityUser();
        
        var result = await _sut.FindByEmailAsync(uniqueUser.Email);

        result.Should().BeNull();
    }

    [Fact]
    public async void FindByEmailAsync_ShouldReturnIdentityUser_WhenUserExists()
    {
        await CreateIdentityUserInPersistent();

        var result = await _sut.FindByEmailAsync(_identityUser.Email);

        result.Should().NotBeNull();
    }

    private IdentityUser CreateIdentityUser() => new IdentityUser
    {
        Email = $"{Guid.NewGuid()}@test.com",
        Salt = _identityUser.Salt,
        Password = _identityUser.Password,
    };

    [Fact]
    public async void CreateAsync_ShouldStoreUser_WhenUserDoesNotExist()
    {
        var uniqueUser = CreateIdentityUser();
        await _sut.CreateAsync(uniqueUser);

        var persistentUser = await _sut.FindByEmailAsync(uniqueUser.Email);
        persistentUser.Should().NotBeNull();
        persistentUser!.Email.Should().Be(uniqueUser.Email);
        persistentUser!.Salt.Should().Be(uniqueUser.Salt);
        persistentUser!.Password.Should().Be(uniqueUser.Password);
    }

    [Fact]
    public async void CreateAsync_ShouldThrow_WhenUserExistst()
    {
        await CreateIdentityUserInPersistent();

        Func<Task> act = () => _sut.CreateAsync(_identityUser);

        await act.Should().ThrowAsync<Exception>();
    }
}