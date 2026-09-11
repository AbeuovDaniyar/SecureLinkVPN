namespace SecureLink.Client;

/// <summary>
/// Single place the client's backend URL lives. The backend runs on the US relay
/// droplet itself (165.227.213.133) rather than a dedicated server or localhost —
/// see the "Backend hosting" note in BUILD_GUIDE.md for why. Uses a self-signed
/// cert (no domain name to get a real one for), so ApiClient must skip certificate
/// validation for this host specifically.
/// </summary>
public static class AppConfig
{
    public const string ApiBaseUrl = "https://165.227.213.133";
}
