using Frame.Domain;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Frame.UnitTests.Helpers;
public static class AuthenticationResultHelper
{
    public static AuthenticationResult GetFailedOne() => new AuthenticationResult
    {
        Succeded = false
    };

    public static AuthenticationResult GetSuccededOne() => new AuthenticationResult
    {
        Succeded = true
    };
}
