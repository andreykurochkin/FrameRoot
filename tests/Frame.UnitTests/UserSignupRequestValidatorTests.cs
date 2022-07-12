using FluentAssertions;
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

    [Fact]
    public void ValidatePassword_ShouldNotFail_WhenDataIsValid()
    {
        var model = new UserSignupRequest 
        { 
            Password = @"1Nyt537*k^4b",
            ConfirmPassword = @"1Nyt537*k^4b",
            Email = "test@test.com",
            FamilyName = "John",
            GivenName = "Smith",
        };

        var result = _sut.Validate(model);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ValidatePassword_ShouldFail_WhenPasswordDoesNotMatchConfirmPassword()
    {
        var model = new UserSignupRequest
        {
            Password = "1Nyt537*k^4b",
            ConfirmPassword = "password",
            Email = "test@test.com",
            FamilyName = "John",
            GivenName = "Smith",
        };

        var result = _sut.Validate(model);

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void ValidateEmail_ShouldFail_WhenDataIsInvalid()
    {
        var model = new UserSignupRequest { Email = "not a valid email" };

        var result = _sut.TestValidate(model);

        result.ShouldHaveValidationErrorFor(_ => _.Email);
    }
}
