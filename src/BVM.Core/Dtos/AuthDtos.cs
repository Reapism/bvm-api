using System.ComponentModel.DataAnnotations;

namespace BVM.Core.Dtos;


public record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(8)] string Password
);

public record LoginResponse(AuthToken Token);

public record RegisterRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(8)] string Password
);

public record RegisterResponse(AuthToken Token);

public record RefreshRequest(
    [Required] string RefreshToken
);

public record RefreshResponse(AuthToken Token);

public record LogoutRequest(
    [Required] string RefreshToken
);

public record LogoutResponse(bool IsSuccessful);

public record AuthToken(bool IsSuccessful, string AccessToken, string RefreshToken, int ExpiresIn)
{
    public static AuthToken Failed() => new(false, string.Empty, string.Empty, 0);
}