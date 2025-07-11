namespace BVM.WebApi.Services;

public interface IExternalAuthProvider
{
    /// <summary>e.g. "google", "facebook", "tiktok", "spotify"</summary>
    string ProviderId { get; }

    /// <summary>Where to send the user to start the OAuth sign-in (code flow).</summary>
    string GetAuthorizationUrl(string redirectUri, string state);

    /// <summary>
    /// Exchange an authorization code for tokens.
    /// </summary>
    Task<OAuthToken> ExchangeCodeAsync(string code, string redirectUri);

    /// <summary>Refresh an access token using a refresh token.</summary>
    Task<OAuthToken> RefreshTokenAsync(string refreshToken);
}
