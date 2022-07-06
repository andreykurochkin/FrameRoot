using Frame.Domain;
using Frame.Infrastructure.Services.Base;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Frame.Infrastructure.Services;
// TODO delete LocalUserService, IUserService move CheckPasswordAsync to 
public class LocalUserService : IUserService
{
    private readonly List<IdentityUser<Guid>> _users = new();
    private readonly IPasswordHasher<IdentityUser<Guid>> _passwordHasher;
    private const string Password = "1234";

    public LocalUserService(IPasswordHasher<IdentityUser<Guid>> passwordHasher)
    {
        _passwordHasher = passwordHasher;
        _users = new List<IdentityUser<Guid>>
        {
            new IdentityUser<Guid>
            {
                Id = Guid.NewGuid(),
                Email = @"test@test.com",
            }
        };
        _users.ForEach(user => user.PasswordHash = _passwordHasher.HashPassword(user, Password));
    }

    public Task<bool> CheckPasswordAsync(Frame.Domain.IdentityUser user, string password)
    {
        var passwordHasher = new PasswordHasher<IdentityUser<Guid>>();
        // /*user*/ should be modified
        var passwordVerificationResult = passwordHasher.VerifyHashedPassword(new IdentityUser<Guid>() /*user*/, "pass" /*user.PasswordHash*/, password);
        var result = passwordVerificationResult == PasswordVerificationResult.Success;
        return Task.FromResult(result);
    }
}
