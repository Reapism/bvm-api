namespace BVM.WebApi.Services;

public class GoogleAuthProvider : IExternalAuthProvider
{
    public string ProviderId => "google";

    private readonly HttpClient _http;
    private readonly GoogleOptions _opts;
    private readonly GoogleAuthorizationCodeFlow _flow; // from Google.Apis.Auth

    public GoogleAuthProvider(
        HttpClient http,
        IOptions<GoogleOptions> opts,
        GoogleAuthorizationCodeFlow flow)
    {
        _http = http;
        _opts = opts.Value;
        _flow = flow;
    }

    public string GetAuthorizationUrl(string redirectUri, string state)
        => _flow.CreateAuthorizationCodeRequest(redirectUri)
                .SetScopes(_opts.Scopes)
                .SetState(state)
                .Build()
                .ToString();

    public async Task<OAuthToken> ExchangeCodeAsync(string code, string redirectUri)
    {
        var token = await _flow.ExchangeCodeForTokenAsync(
            userId: null, code, redirectUri, CancellationToken.None);

        return new OAuthToken
        {
            AccessToken  = token.AccessToken,
            RefreshToken = token.RefreshToken,
            ExpiresAt    = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresInSeconds ?? 0)
        };
    }

    public async Task<OAuthToken> RefreshTokenAsync(string refreshToken)
    {
        var token = await _flow.RefreshTokenAsync(
            userId: null, refreshToken, CancellationToken.None);

        return new OAuthToken
        {
            AccessToken  = token.AccessToken,
            RefreshToken = token.RefreshToken,
            ExpiresAt    = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresInSeconds ?? 0)
        };
    }
}
