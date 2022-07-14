using Frame.Domain;
using Frame.Infrastructure.Options;
using Frame.Infrastructure.Providers;
using Frame.Infrastructure.Providers.Base;
using Frame.Infrastructure.Repositories;
using Frame.IntegrationTests.Fixtures;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Frame.IntegrationTests;

public class RefreshTokenMongoRepositoryTests : IClassFixture<MongoDbFixture>
{
    private readonly MongoDbFixture _fixture;
    private readonly RefreshTokenMongoRepository _sut;
    private readonly RefreshToken _refreshToken;
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly IGuidProvider _guidProvider;
    private readonly IRefreshTokenProvider _refreshTokenProvider;
    private readonly ISecurityTokenProvider _securityTokenProvider;
    public RefreshTokenMongoRepositoryTests(MongoDbFixture fixture)
    {
        //_fixture = fixture;
        //_guidProvider = new MongoGuidProvider();
        //_dateTimeProvider = new DateTimeNowProvider();
        //_refreshTokenProvider = new DefaultRefreshTokenProvider(_dateTimeProvider, _guidProvider);
        //var expiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJiNGU1YTFmYi1hODE1LTQ4N2ItYTg0OC1iMDZjYzRhNGMzZDEiLCJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwiaWRlbnRpdHlVc2VySWQiOiIyZDc5NjE5Zi01MzRhLTRhNGEtOTJhNi1hZmUyNjljYTYwZGQiLCJuYmYiOjE2NTcyNjkyNTcsImV4cCI6MTY1NzI2OTI1OSwiaWF0IjoxNjU3MjY5MjU3fQ.S6sGap0trL2euXx--_XmnVPwynyYW97sJ5HpASunuBs";
        //JwtOptions jwtOptions = new JwtOptions
        //{
        //    Secret = "01234567890123456789012345678912",
        //    TokenLifeTime = new TimeSpan(0, 0, 15),
        //};
        //_securityTokenProvider = new DefaultSecurityTokenProvider(jwtOptions, _guidProvider); 
        ////var securityAccessToken = _securityTokenProvider.GetSecurityToken(identityUser);
        //_refreshToken = _refreshTokenProvider.GetRefreshToken(securityAccessToken, Frame.UnitTests.Helpers.IdentityUserHelper.GetOne());
        //_sut = new RefreshTokenMongoRepository(_fixture.MongoClient, _fixture.MongoDbOptions);
    }

    public Task CreateAsync_ShouldCreateRefreshToken_WhenPersistentDoesNotHaveToken()
    {
        throw new NotImplementedException();
        //RefreshToken refreshToken;

        //var result = await _sut.CreateAsync(refreshToken);
    }
}
