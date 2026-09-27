using SecureLink.Api.Models;

namespace SecureLink.Api.Services;

public interface IRelayGatewayService
{
    RelayServer GetRelay(string region);

    /// Picks a free /32 inside the relay's tunnel subnet for this session.
    string AssignTunnelIp(RelayServer relay, IEnumerable<string> ipsAlreadyInUse);

    /// Throws RelayUnavailableException if the relay can't be reached or rejects the peer.
    Task AddPeerAsync(RelayServer relay, string clientPublicKey, string allowedIp);

    /// Never throws — see the comments in RelayGatewayService.RemovePeerAsync.
    Task RemovePeerAsync(string region, string clientPublicKey);
}
