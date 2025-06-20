using System.ComponentModel.DataAnnotations;

namespace BVM.Core.Dtos;

public record LoginRequest([Required] string Email, [Required] string Password);

public record AuthToken(bool IsSuccessful, string AccessToken, string RefreshToken, int ExpiresIn);
