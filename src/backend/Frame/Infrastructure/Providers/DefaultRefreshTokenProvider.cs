using Frame.Domain;
using Frame.Infrastructure.Providers.Base;
using Microsoft.IdentityModel.Tokens;

namespace Frame.Infrastructure.Providers;
public class DefaultRefreshTokenProvider : IRefreshTokenProvider
{
    private readonly IDateTimeProvider _dateTimeProvider;
    private readonly IGuidProvider _guidProvider;

    public DefaultRefreshTokenProvider(IDateTimeProvider dateTimeProvider, IGuidProvider guidProvider)
    {
        _dateTimeProvider = dateTimeProvider;
        _guidProvider = guidProvider;
    }

    public RefreshToken GetRefreshToken(SecurityToken accessToken, IdentityUser identityUser)
    {
        var cachedUtcNow = _dateTimeProvider.GetDateTime().ToUniversalTime();
        var result = new RefreshToken
        {
            Token = _guidProvider.GetGuid() /*Guid.NewGuid().ToString()*/,
            JwtId = accessToken.Id,
            UserId = identityUser.Id.ToString(),
            CreationDate = cachedUtcNow,
            ExpiryDate = cachedUtcNow.AddMonths(6),
        };
        return result;
    }
}