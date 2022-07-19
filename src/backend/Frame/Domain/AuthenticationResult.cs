﻿using Frame.Contracts.V1.Responses;

namespace Frame.Domain;
public class AuthenticationResult
{
    public bool Succeded { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public IEnumerable<string>? Errors { get; set; }
    public IEnumerable<ModelFieldError>? ModelFieldErrors { get; set; }
}
