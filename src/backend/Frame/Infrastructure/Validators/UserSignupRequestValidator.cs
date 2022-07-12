using FluentValidation;
using Frame.Contracts.V1.Requests;

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
            .WithMessage($"{nameof(UserSignupRequest.Password)} doesn`t have any upper case charatets");
        RuleFor(request => request.Password).NotEqual(request => request.ConfirmPassword)
            .WithMessage($"{nameof(UserSignupRequest.Password)} doesn`t match {nameof(UserSignupRequest.ConfirmPassword)}");
    }
}
