using FluentValidation.TestHelper;
using Frame.Contracts.V1.Requests;
using Frame.Infrastructure.Validators;
using System.Collections;
using System.Collections.Generic;
using Xunit;

namespace Frame.UnitTests;

public class InvalidStrings : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[] { null! };
        yield return new object[] { string.Empty };
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public class UserSignupRequestValidatorTests
{
    private readonly UserSignupRequestValidator _sut;
    public UserSignupRequestValidatorTests()
    {
        _sut = new UserSignupRequestValidator();
    }

    [Theory]
    [ClassData(typeof(InvalidStrings))]
    public void ValidatePassword_ShouldFail_WhenDataIsInvalid(string? password)
    {
        var model = new UserSignupRequest { Password = password };

        var result = _sut.TestValidate(model);

        result.ShouldHaveValidationErrorFor(_ => _.Password);
    }
}
