namespace SecureLink.Client.Services;

public enum TunnelHealthState
{
    /// <summary>Just connected; the first handshake hasn't completed yet.</summary>
    Establishing,
    /// <summary>The relay answered recently.</summary>
    Healthy,
    /// <summary>The relay has stopped answering.</summary>
    Lost,
}

/// <summary>
/// Decides whether the tunnel is really alive, from the time of WireGuard's last
/// successful handshake with the relay. WireGuard has no "connected" state of its
/// own — the tunnel service keeps running and the app would keep saying "Connected"
/// even if the relay went away — so this is the only honest signal.
/// </summary>
public static class TunnelHealth
{
    // While a tunnel is in use WireGuard re-handshakes about every 2 minutes (and
    // PersistentKeepalive = 25 keeps ours in use), and it discards a session whose
    // handshake is older than 180 seconds. So "older than 180s" means the relay is
    // genuinely not answering, not merely idle.
    public static readonly TimeSpan StaleAfter = TimeSpan.FromSeconds(180);

    // A first handshake normally completes in well under a second; allow for a slow link.
    public static readonly TimeSpan EstablishGrace = TimeSpan.FromSeconds(15);

    public static TunnelHealthState Evaluate(DateTime? lastHandshakeUtc, DateTime connectedSinceUtc, DateTime nowUtc)
    {
        if (lastHandshakeUtc is null)
            return nowUtc - connectedSinceUtc <= EstablishGrace ? TunnelHealthState.Establishing : TunnelHealthState.Lost;

        return nowUtc - lastHandshakeUtc.Value <= StaleAfter ? TunnelHealthState.Healthy : TunnelHealthState.Lost;
    }
}
