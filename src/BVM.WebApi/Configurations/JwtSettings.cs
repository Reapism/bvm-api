namespace BVM.WebApi.Configurations;

public record JwtSettings(string Key, string Issuer, string Audience);
