using FluentValidation;
using Frame.Contracts.V1.Requests;
using System.Net;

namespace Frame.Infrastructure.Validators;
public class UserSignupRequestValidator : AbstractValidator<UserSignupRequest>
{
    public UserSignupRequestValidator()
    {
        RuleFor(request => request.Password).NotNull()
            .WithMessage($"{nameof(UserSignupRequest.Password)} is null or empty");
        RuleFor(request => request.Password).NotEmpty()
            .WithMessage($"{nameof(UserSignupRequest.Password)} is null or empty");
        RuleFor(request => request.Password).MinimumLength(7)
            .WithMessage($"{nameof(UserSignupRequest.Password)} is less then 7 characters");
        RuleFor(request => request.Password).Matches(@"[0-9]+")
            .WithMessage($"{nameof(UserSignupRequest.Password)} doesn`t have any numbers");
        RuleFor(request => request.Password).Matches(@"[A-Z]+")
            .WithMessage($"{nameof(UserSignupRequest.Password)} doesn`t have any upper case characters");
        RuleFor(request => request.Password).Equal(request => request.ConfirmPassword)
            .WithMessage($"{nameof(UserSignupRequest.Password)} doesn`t match {nameof(UserSignupRequest.ConfirmPassword)}");

        RuleFor(request => request.Password).NotNull()
            .WithMessage($"{nameof(UserSignupRequest.Password)} is null or empty");
        RuleFor(request => request.Password).NotEmpty()
            .WithMessage($"{nameof(UserSignupRequest.Password)} is null or empty");
        RuleFor(request => request.Email).EmailAddress()
            .WithMessage("Is not a valid email address");
    }
}
