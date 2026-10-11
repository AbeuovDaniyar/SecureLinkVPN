namespace SecureLink.Client;

/// <summary>
/// Single place the client's backend URL lives. The backend runs on the US relay
/// droplet itself (165.227.213.133) rather than a dedicated server or localhost.
/// Uses a self-signed cert (no domain name to get a real one for), so ApiClient
/// pins that exact certificate instead of using normal chain validation.
/// </summary>
public static class AppConfig
{
    public const string ApiBaseUrl = "https://165.227.213.133";
}
