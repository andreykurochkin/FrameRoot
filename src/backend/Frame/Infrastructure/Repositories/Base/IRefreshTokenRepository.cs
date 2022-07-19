using Frame.Domain;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Frame.Infrastructure.Repositories.Base;
public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetRefreshTokenByJwtIdAsync(string jwtId);
    Task CreateAsync(RefreshToken? refreshToken);
    Task<ReplaceOneResult> ReplaceOneAsync(RefreshToken? refreshToken);
}
