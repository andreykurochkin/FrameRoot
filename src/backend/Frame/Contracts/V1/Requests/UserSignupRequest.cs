using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Frame.Contracts.V1.Requests;
public class UserSignupRequest
{
    public string? Email { get; set; }
    public string? Password { get; set; }
    public string? ConfirmPassword { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime? Ts { get; set; }
}
