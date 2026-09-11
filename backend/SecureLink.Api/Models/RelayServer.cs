namespace SecureLink.Api.Models;

// Bound from the "Relays" section of appsettings.json — static metadata about
// the two relays, not a database table. See BUILD_GUIDE.md Phase 2 for why.
public class RelayServer
{
    public string Region { get; set; } = string.Empty;
    public string Endpoint { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string ManagementUrl { get; set; } = string.Empty;
    public string ManagementToken { get; set; } = string.Empty;
    public string TunnelSubnet { get; set; } = string.Empty;
}
