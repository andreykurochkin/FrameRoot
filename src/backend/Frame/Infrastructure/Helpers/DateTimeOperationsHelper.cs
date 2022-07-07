using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Frame.Infrastructure.Helpers;
public class DateTimeOperationsHelper
{
    public static DateTime GetExpiryUnixDateTimeUtc(Claim jwtExpClaim)
    {
        var expiryDateUnix = long.Parse(jwtExpClaim.Value);
        var expiryDateUnixUtc = new DateTime(year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0, kind: DateTimeKind.Utc).AddSeconds(expiryDateUnix);
        return expiryDateUnixUtc;
    }
}
