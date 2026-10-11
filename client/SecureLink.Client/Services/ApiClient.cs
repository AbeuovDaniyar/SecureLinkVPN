using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;

namespace SecureLink.Client.Services;

public record ConnectResult(Guid SessionId, string RelayPublicKey, string RelayEndpoint, string TunnelIp, string TunnelSubnet);

public class ApiClient
{
    // The backend runs on the US relay droplet with a self-signed cert (no domain
    // name to get a trusted one for — see AppConfig.cs). Rather than disabling
    // certificate validation entirely (which would accept ANY cert from anywhere,
    // defeating TLS), we trust to only this specific certificate
    private const string PinnedCertThumbprint =
        "053F1809D67ED37B2A4AD5C3371CB70D0DE4994626886CC56DEA2CCCAD6D8713";

    private readonly HttpClient _http;
    private readonly TokenStore _tokenStore;

    public string? AuthToken { get; set; }

    /// <summary>When the current token stops being accepted by the backend (UTC).</summary>
    public DateTime TokenExpiresAtUtc { get; private set; }

    public ApiClient(string baseUrl, TokenStore? tokenStore = null)
    {
        _tokenStore = tokenStore ?? new TokenStore();

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert is not null &&
                cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)
                    .Equals(PinnedCertThumbprint.Replace(" ", ""), StringComparison.OrdinalIgnoreCase),
        };
        // HttpClient's default Timeout is 100 seconds so we change it to 10sec, its better to fail quickly then wait for long and still fail.
        _http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(10) };

        // Open a fresh connection for every request instead of reusing a pooled one.
        // A pooled connection keeps the route it was opened on: one opened while the
        // tunnel was up (e.g. logging in right after a crash left the tunnel running)
        // dies the moment the tunnel is torn down, and the next call on it fails with
        // "connection forcibly closed" — which made startup cleanup skip closing the
        // stale session, so the next Connect got 409. The client makes only a handful
        // of calls, so the extra handshake per request costs nothing noticeable.
        _http.DefaultRequestHeaders.ConnectionClose = true;
    }

    private void AttachAuth()
    {
        if (!string.IsNullOrEmpty(AuthToken))
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);
    }

    // response.EnsureSuccessStatusCode() only ever surfaces the status code (e.g.
    // "409 (Conflict)"), not showing actuall backend error, this ensures the proper message is returned
    private static async Task EnsureSuccessWithMessageAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;
        var body = await response.Content.ReadAsStringAsync();
        throw new InvalidOperationException(string.IsNullOrWhiteSpace(body)
            ? $"Request failed ({(int)response.StatusCode} {response.StatusCode})."
            : body.Trim());
    }

    public async Task LoginAsync(string email, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/login", new { email, password });
        await EnsureSuccessWithMessageAsync(response);
        AcceptToken((await response.Content.ReadFromJsonAsync<AuthResponseDto>())!);
    }

    public async Task RegisterAsync(string email, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/register", new { email, password });
        await EnsureSuccessWithMessageAsync(response);
        AcceptToken((await response.Content.ReadFromJsonAsync<AuthResponseDto>())!);
    }

    // Every token the backend hands out goes through here: it becomes the one this
    // client sends, and it replaces the copy in Windows Credential Manager.
    private void AcceptToken(AuthResponseDto auth)
    {
        AuthToken = auth.Token;
        TokenExpiresAtUtc = DateTime.SpecifyKind(auth.ExpiresAt, DateTimeKind.Utc);
        try
        {
            _tokenStore.Save(new StoredToken(auth.Token, TokenExpiresAtUtc));
        }
        catch (Exception)
        {
            // Not being able to save only costs the user a sign-in next launch;
            // it must never fail the sign-in that just succeeded.
        }
    }

    /// <summary>
    /// Signs in with the token saved by a previous run, if there is one and the
    /// backend still accepts it. Returns false when the user has to sign in again.
    /// </summary>
    public async Task<bool> TryRestoreSessionAsync()
    {
        var saved = _tokenStore.Load();
        if (saved is null)
            return false;

        if (saved.ExpiresAtUtc <= DateTime.UtcNow)
        {
            _tokenStore.Clear();
            return false;
        }

        AuthToken = saved.Token;
        TokenExpiresAtUtc = saved.ExpiresAtUtc;
        try
        {
            // Refreshing proves the backend still accepts the token (it may have been
            // issued for an account that no longer exists) and extends it in one call.
            await RefreshTokenAsync();
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            SignOut();
            return false;
        }
        catch (Exception)
        {
            // Backend unreachable: can't tell whether the token is good. Keep it for
            // next time, but make the user sign in now rather than open the main
            // window in a state where every call might fail.
            AuthToken = null;
            _http.DefaultRequestHeaders.Authorization = null;
            return false;
        }
    }

    /// <summary>
    /// Swaps the current token for a fresh one. Throws UnauthorizedAccessException
    /// if the backend no longer accepts the current token.
    /// </summary>
    public async Task RefreshTokenAsync()
    {
        AttachAuth();
        var response = await _http.PostAsync("/api/auth/refresh", null);
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            throw new UnauthorizedAccessException("Your sign-in has expired. Please sign in again.");
        await EnsureSuccessWithMessageAsync(response);
        AcceptToken((await response.Content.ReadFromJsonAsync<AuthResponseDto>())!);
    }

    /// <summary>
    /// Refreshes the token when it has less than <paramref name="within"/> left.
    /// Called on a timer so a long VPN session never outlives its token.
    /// </summary>
    public async Task RefreshTokenIfExpiringAsync(TimeSpan within)
    {
        if (string.IsNullOrEmpty(AuthToken) || TokenExpiresAtUtc - DateTime.UtcNow > within)
            return;
        await RefreshTokenAsync();
    }

    /// <summary>Forgets the token, both in memory and in Windows Credential Manager.</summary>
    public void SignOut()
    {
        AuthToken = null;
        TokenExpiresAtUtc = default;
        _http.DefaultRequestHeaders.Authorization = null;
        _tokenStore.Clear();
    }

    public async Task<ConnectResult> ConnectAsync(string region, string clientPublicKey)
    {
        AttachAuth();
        var response = await _http.PostAsJsonAsync("/api/sessions/connect", new { region, clientPublicKey });
        await EnsureSuccessWithMessageAsync(response);
        return (await response.Content.ReadFromJsonAsync<ConnectResult>())!;
    }

    public async Task DisconnectAsync(Guid sessionId)
    {
        AttachAuth();
        var response = await _http.PostAsJsonAsync("/api/sessions/disconnect", new { sessionId });
        await EnsureSuccessWithMessageAsync(response);
    }

    /// <summary>
    /// Returns the id of this account's active session on the backend, if any, or
    /// null if there isn't one. Used at startup to detect a session that's still
    /// "active" server-side (and still holding a real peer on the relay) from a
    /// previous run that ended without calling DisconnectAsync — e.g. the app was
    /// closed or killed after a successful Connect.
    /// </summary>
    public async Task<Guid?> GetActiveSessionIdAsync()
    {
        AttachAuth();
        var response = await _http.GetAsync("/api/sessions/active");
        if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
            return null;
        await EnsureSuccessWithMessageAsync(response);
        var body = await response.Content.ReadFromJsonAsync<ActiveSessionDto>();
        return body?.Id;
    }

    private record AuthResponseDto(string Token, DateTime ExpiresAt);
    private record ActiveSessionDto(Guid Id);
}
