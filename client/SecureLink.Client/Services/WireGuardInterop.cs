using System.Diagnostics;
using System.IO;
using System.Threading;

namespace SecureLink.Client.Services;

/// <summary>
/// Wraps the official WireGuard-for-Windows CLI (wireguard.exe / wg.exe) rather than
/// calling wireguard-nt directly. This is the "fallback" path called out in the SDD
/// (Section 3.1) — start here; only reach for the raw driver API if you need
/// tighter control (e.g. no tray icon flash from the official app) and have time
/// left in the schedule for it.
///
/// Requires the WireGuard for Windows MSI installed (ships wireguard.exe + wg.exe,
/// typically under C:\Program Files\WireGuard\).
/// </summary>
public class WireGuardInterop
{
    private const string WireGuardExe = @"C:\Program Files\WireGuard\wireguard.exe";
    private const string WgExe = @"C:\Program Files\WireGuard\wg.exe";
    private const string TunnelName = "securelink";
    private readonly string _configPath = Path.Combine(Path.GetTempPath(), $"{TunnelName}.conf");

    public (string privateKey, string publicKey) GenerateKeyPair()
    {
        var privateKey = RunAndCapture(WgExe, args: "genkey").Trim();
        // `wg pubkey` reads the private key from stdin, not as a CLI argument
        // (`wg pubkey <key>` just prints usage and exits 1) — see wg(8).
        var publicKey = RunAndCapture(WgExe, stdin: privateKey, args: "pubkey").Trim();
        return (privateKey, publicKey);
    }

    public void BringUpTunnel(string privateKey, string localAddress, string relayPublicKey, string relayEndpoint)
    {
        // DNS matters here: with no DNS server set, Windows falls back to the
        // original adapter's DNS (the local router), but the kill switch's
        // default-outbound-block policy correctly treats that as a leak and drops
        // it — so name resolution just fails outright even though raw-IP routing
        // through the tunnel works fine. Pointing DNS at a public resolver routes
        // lookups through the tunnel itself (sourced from the tunnel's own local
        // IP, matching the kill switch's allow-tunnel rule).
        var config = $"""
            [Interface]
            PrivateKey = {privateKey}
            Address = {localAddress}
            DNS = 1.1.1.1

            [Peer]
            PublicKey = {relayPublicKey}
            Endpoint = {relayEndpoint}
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 25
            """;

        File.WriteAllText(_configPath, config);

        // /installtunnelservice registers + starts it as a Windows service; requires admin.
        Run(WireGuardExe, $"/installtunnelservice \"{_configPath}\"");
    }

    public void TearDownTunnel()
    {
        try
        {
            Run(WireGuardExe, $"/uninstalltunnelservice {TunnelName}");
        }
        catch (InvalidOperationException)
        {
            // wireguard.exe has been observed reporting a nonzero exit code here even
            // when the service is actually removed a moment later (the uninstall isn't
            // necessarily synchronous with the CLI returning) -- verify the real
            // outcome instead of trusting the exit code alone, so a harmless timing
            // blip doesn't surface to the user as a scary "teardown failed" error when
            // nothing is actually wrong.
            for (var i = 0; i < 10 && OrphanedTunnelServiceExists(); i++)
                Thread.Sleep(500);

            if (OrphanedTunnelServiceExists())
                throw; // still there after waiting -- the original failure was real.
        }

        if (File.Exists(_configPath))
            File.Delete(_configPath);
    }

    /// <summary>
    /// True if a "securelink" tunnel Windows service is currently installed — e.g. left
    /// behind by a previous run that was killed or crashed after BringUpTunnel()
    /// installed it but before TearDownTunnel() could remove it. That service runs
    /// independently of this app: it survives the app closing, keeps its
    /// AllowedIPs = 0.0.0.0/0 route (i.e. it owns the machine's default route) pointed
    /// at a peer nobody is maintaining anymore, and silently breaks internet access
    /// with no obvious cause. WireGuard for Windows names these services
    /// "WireGuardTunnel$&lt;name&gt;" — see the tunnel service manager in the official client.
    /// </summary>
    public bool OrphanedTunnelServiceExists()
    {
        var psi = new ProcessStartInfo("sc.exe", $"query \"WireGuardTunnel${TunnelName}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var process = Process.Start(psi)!;
        process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        // sc query exits 0 if the service exists (running or not), non-zero
        // (1060, "service does not exist") if it doesn't.
        return process.ExitCode == 0;
    }

    public bool IsHandshakeActive()
    {
        // TODO (Phase 5 / HealthMonitor): parse the output and compare against
        // DateTimeOffset.UtcNow to detect a stale/dropped tunnel, not just "any output".
        var output = RunAndCapture(WgExe, args: ["show", TunnelName, "latest-handshakes"]);
        return !string.IsNullOrWhiteSpace(output);
    }

    /// <summary>
    /// Real received/sent byte counts for the current tunnel, straight from
    /// `wg show securelink transfer` (format: "&lt;peer-pubkey&gt;\t&lt;rx-bytes&gt;\t&lt;tx-bytes&gt;").
    /// Throws if the tunnel isn't up — callers should only poll this while connected.
    /// </summary>
    public (long rxBytes, long txBytes) GetTransferStats()
    {
        var output = RunAndCapture(WgExe, args: ["show", TunnelName, "transfer"]).Trim();
        var parts = output.Split('\t');
        if (parts.Length < 3 || !long.TryParse(parts[1], out var rx) || !long.TryParse(parts[2], out var tx))
            return (0, 0);
        return (rx, tx);
    }

    private static void Run(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            Verb = "runas", // elevation prompt — installing a tunnel service needs admin
        };
        using var process = Process.Start(psi);
        process?.WaitForExit();

        // UseShellExecute=false + Verb=runas still launches via ShellExecute under the
        // hood, so we can't redirect output for a good error message — but we can at
        // least fail loudly instead of silently continuing as if the tunnel/rule came
        // up when it didn't (that's how you end up with a half-up tunnel nobody knows
        // to tear down).
        if (process is not null && process.ExitCode != 0)
            throw new InvalidOperationException($"{exe} {args} failed (exit code {process.ExitCode}).");
    }

    private static string RunAndCapture(string exe, string? stdin = null, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin is not null,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var process = Process.Start(psi)!;

        if (stdin is not null)
        {
            process.StandardInput.Write(stdin);
            process.StandardInput.Close();
        }

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
            throw new InvalidOperationException($"{exe} {string.Join(' ', args)} failed ({process.ExitCode}): {error.Trim()}");

        return output;
    }
}
