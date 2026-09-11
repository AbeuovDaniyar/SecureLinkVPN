using System.Diagnostics;

namespace SecureLink.Client.Services;

/// <summary>
/// Blocks all outbound traffic except the VPN tunnel while connected, using
/// `netsh advfirewall`. If the tunnel drops, this is what stops other traffic from
/// silently falling back to the raw internet connection (SDD Section 3.3).
///
/// This does NOT use an explicit unscoped "block everything" RULE — Windows
/// Firewall evaluates explicit Block rules before explicit Allow rules, so an
/// unscoped Block rule always wins over any narrower Allow rule regardless of
/// specificity. An earlier version of this class did exactly that (one rule
/// blocking all outbound, one allowing the relay's IP) and it blocked
/// essentially all real traffic, including to the relay itself, once enabled.
/// Instead, this flips the *default outbound policy* to Block: default-policy
/// fallback is evaluated after explicit rules, so narrow Allow rules below
/// correctly take effect.
/// </summary>
public class KillSwitchService
{
    private const string RuleName = "SecureLink-KillSwitch";
    private bool _enabled;

    public bool IsEnabled => _enabled;

    /// <param name="relayEndpoint">"ip:port" of the relay — allows the WireGuard
    /// transport's own encrypted UDP packets (sourced from the physical adapter)
    /// to reach it.</param>
    /// <param name="tunnelIp">This client's tunnel-assigned address (e.g.
    /// "10.8.0.5/32") — allows all traffic actually sourced from the tunnel
    /// interface, i.e. everything genuinely going through the VPN, regardless of
    /// its final destination.</param>
    public void Enable(string relayEndpoint, string tunnelIp)
    {
        var relayIp = relayEndpoint.Split(':')[0];
        var tunnelAddress = tunnelIp.Split('/')[0];

        // Assumes the user hasn't customized inbound policy away from Windows'
        // standard default (blockinbound) -- true for the vast majority of
        // machines. netsh only sets both directions together.
        RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");

        RunNetsh($"advfirewall firewall add rule name=\"{RuleName}-allow-relay\" dir=out action=allow remoteip={relayIp} enable=yes");
        RunNetsh($"advfirewall firewall add rule name=\"{RuleName}-allow-tunnel\" dir=out action=allow localip={tunnelAddress} enable=yes");

        _enabled = true;
    }

    // Deliberately NOT gated on _enabled: a fresh KillSwitchService instance (a new
    // app launch) always starts with _enabled = false in memory, even if a previous
    // run crashed while connected and left the machine-wide outbound policy stuck
    // on Block. MainWindow's startup orphan-check calls this unconditionally for
    // exactly that reason — every operation here is idempotent (restoring a policy
    // that's already correct, or deleting a rule that's already gone, are both
    // harmless no-ops), so there's no cost to always attempting it.
    public void Disable()
    {
        RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
        RunNetsh($"advfirewall firewall delete rule name=\"{RuleName}-allow-relay\"");
        RunNetsh($"advfirewall firewall delete rule name=\"{RuleName}-allow-tunnel\"");

        _enabled = false;
    }

    private static void RunNetsh(string args)
    {
        var psi = new ProcessStartInfo("netsh", args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            Verb = "runas",
        };
        using var process = Process.Start(psi);
        process?.WaitForExit();
    }
}
