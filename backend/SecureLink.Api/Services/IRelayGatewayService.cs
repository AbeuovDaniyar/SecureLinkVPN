using SecureLink.Api.Models;

namespace SecureLink.Api.Services;

public interface IRelayGatewayService
{
    RelayServer GetRelay(string region);

    /// Picks a free /32 inside the relay's tunnel subnet for this session.
    string AssignTunnelIp(RelayServer relay, IEnumerable<string> ipsAlreadyInUse);

    Task AddPeerAsync(RelayServer relay, string clientPublicKey, string allowedIp);
    Task RemovePeerAsync(RelayServer relay, string clientPublicKey);
}
