namespace Frame.Contracts.V1.Responses;

public record ModelFieldError
{
    public string? FieldName { get; init; }
    public string? Error { get; init; }
    public ModelFieldError(string? fieldName, string? error) => (FieldName, Error) = (fieldName, error);
}
