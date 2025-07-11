// OAuthOptions.cs
namespace BVM.Core.Options
{
    /// <summary>
    /// Configuration for Google / YouTube OAuth
    /// </summary>
    public record GoogleOptions(
        string ClientId,
        string ClientSecret,
        string RedirectUri,
        string[] Scopes,
        string AuthorizeEndpoint,
        string TokenEndpoint,
        string UserInfoEndpoint,
        string? RevocationEndpoint // optional: only required if you intend to support revoking tokens
    );

    /// <summary>
    /// Configuration for Facebook OAuth
    /// </summary>
    public record FacebookOptions(
        string ClientId,
        string ClientSecret,
        string RedirectUri,
        string[] Scopes,
        string AuthorizeEndpoint,
        string TokenEndpoint,
        string UserInfoEndpoint
    );

    /// <summary>
    /// Configuration for Instagram OAuth
    /// </summary>
    public record InstagramOptions(
        string ClientId,
        string ClientSecret,
        string RedirectUri,
        string[] Scopes,
        string AuthorizeEndpoint,
        string TokenEndpoint,
        string UserInfoEndpoint
    );

    /// <summary>
    /// Configuration for TikTok OAuth
    /// </summary>
    public record TikTokOptions(
        string ClientId,
        string ClientSecret,
        string RedirectUri,
        string[] Scopes,
        string AuthorizeEndpoint,
        string TokenEndpoint,
        string? RevokeEndpoint // optional: TikTok’s revoke endpoint
    );
}
