namespace Frame.Contracts.V1.Responses;

public record ModelFieldError
{
    public string? FieldName { get; init; }
    public string? Error { get; init; }
    public ModelFieldError(string? fieldName, string? error) => (FieldName, Error) = (fieldName, error);
}

public record ModelPasswordFieldError : ModelFieldError
{
    public ModelPasswordFieldError(string? error) : base("password", error) { }
}

public record ModelEmailFieldError : ModelFieldError
{
    public ModelEmailFieldError(string? error) : base("email", error) { }
}