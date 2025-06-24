namespace BVM.WebApi.Configurations;

public class JwtSettings
{
    public const int RefreshTokenExpirationDays = 7;

    public const int AccessTokenExpirationMins = 15;

    public string Secret { get; set; } = default!;
    public string Issuer { get; set; } = default!;
    public string Audience { get; set; } = default!;
    public TimeSpan AccessTokenExpiration { get; } = TimeSpan.FromMinutes(AccessTokenExpirationMins);
    public TimeSpan RefreshTokenExpiration { get; } = TimeSpan.FromDays(RefreshTokenExpirationDays);
}