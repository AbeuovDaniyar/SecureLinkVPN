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
    // defeating TLS), pin to this specific certificate's SHA-256 thumbprint so only
    // *this* known cert is accepted. Regenerate this if the server's cert is ever
    // rotated (e.g. after switching to a real domain + Let's Encrypt, this whole
    // pinning block should be removed instead).
    private const string PinnedCertThumbprint =
        "053F1809D67ED37B2A4AD5C3371CB70D0DE4994626886CC56DEA2CCCAD6D8713";

    private readonly HttpClient _http;

    // TODO (Phase 4): load from Windows Credential Manager instead of a field.
    public string? AuthToken { get; set; }

    public ApiClient(string baseUrl)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                cert is not null &&
                cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)
                    .Equals(PinnedCertThumbprint.Replace(" ", ""), StringComparison.OrdinalIgnoreCase),
        };
        // HttpClient's default Timeout is 100 seconds -- far too long for a UI to sit
        // frozen on a single slow/hung request (this link has been observed needing
        // multiple TLS renegotiations, and a request over the VPN tunnel itself is
        // inherently less predictable than a normal LAN call). Every call site treats
        // a failure here as recoverable, so failing fast is strictly better than
        // making the user wait to find out.
        _http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(10) };
    }

    private void AttachAuth()
    {
        if (!string.IsNullOrEmpty(AuthToken))
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);
    }

    // response.EnsureSuccessStatusCode() only ever surfaces the status code (e.g.
    // "409 (Conflict)"), throwing away the backend's actual message ("An account
    // with that email already exists."). Read the body instead so callers show
    // users something they can act on.
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
        var body = await response.Content.ReadFromJsonAsync<AuthResponseDto>();
        AuthToken = body!.Token;
    }

    public async Task RegisterAsync(string email, string password)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/register", new { email, password });
        await EnsureSuccessWithMessageAsync(response);
        var body = await response.Content.ReadFromJsonAsync<AuthResponseDto>();
        AuthToken = body!.Token;
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
