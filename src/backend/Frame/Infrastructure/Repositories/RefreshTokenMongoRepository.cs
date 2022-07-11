using Frame.Domain;
using Frame.Infrastructure.Repositories.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Frame.Infrastructure.Repositories;
public class RefreshTokenMongoRepository : IRefreshTokenRepository
{
    public Task<RefreshToken?> GetRefreshTokenByJwtIdAsync(string jwtId)
    {
        throw new NotImplementedException();
    }

    public Task SaveChangesAsync(RefreshToken refreshToken)
    {
        throw new NotImplementedException();
    }
}
