using System.Diagnostics;
using System.IO;
using System.Threading;

namespace SecureLink.Client.Services;

/// <summary>
/// Wraps the official WireGuard rather than
/// calling wireguard-nt directly.
/// </summary>
public class WireGuardInterop
{
    private const string WireGuardExe = @"C:\Program Files\WireGuard\wireguard.exe";
    private const string WgExe = @"C:\Program Files\WireGuard\wg.exe";
    private const string TunnelName = "securelink";

    /// <summary>True when both WireGuard programs this class drives are present.</summary>
    public static bool IsInstalled => File.Exists(WireGuardExe) && File.Exists(WgExe);
    private readonly string _configPath = Path.Combine(Path.GetTempPath(), $"{TunnelName}.conf");

    public (string privateKey, string publicKey) GenerateKeyPair()
    {
        var privateKey = RunAndCapture(WgExe, args: "genkey").Trim();
        // `wg pubkey` reads the private key from stdin, not as a CLI argument
        var publicKey = RunAndCapture(WgExe, stdin: privateKey, args: "pubkey").Trim();
        return (privateKey, publicKey);
    }

    public void BringUpTunnel(string privateKey, string localAddress, string relayPublicKey, string relayEndpoint)
    {
        // DNS matters here: with no DNS server set, Windows falls back to the
        // original adapter's DNS (the local router), but the kill switch's
        // default-outbound-block policy correctly treats that as a leak and drops
        // it, so name resolution just fails outright even though raw-IP routing
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

        // registers + starts it as a Windows service;
        Run(WireGuardExe, $"/installtunnelservice \"{_configPath}\"");
    }

    public void TearDownTunnel()
    {
        InvalidOperationException? uninstallError = null;
        // Only ask WireGuard to remove a tunnel that exists. It may already be gone
        // (removed by hand, or by WireGuard's own app), and there is nothing to do then.
        if (OrphanedTunnelServiceExists())
        {
            try
            {
                Run(WireGuardExe, $"/uninstalltunnelservice {TunnelName}");
            }
            catch (InvalidOperationException ex)
            {
                // A non-zero exit alone isn't a failure — the service check below decides.
                uninstallError = ex;
            }
        }

        // Verify real removal regardless of the exit code: the service can linger
        // briefly (marked for deletion) even after a successful uninstall, and a
        // failed uninstall may still have removed it.
        for (var i = 0; i < 10 && OrphanedTunnelServiceExists(); i++)
            Thread.Sleep(500);

        if (OrphanedTunnelServiceExists())
            throw uninstallError ?? new InvalidOperationException(
                $"Tunnel service WireGuardTunnel${TunnelName} still exists after uninstall.");

        if (File.Exists(_configPath))
            File.Delete(_configPath);
    }


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

    /// <summary>
    /// When the tunnel last completed a handshake with the relay (UTC), or null if
    /// it hasn't yet. Read from `wg show securelink latest-handshakes`
    /// (format: "&lt;peer-pubkey&gt;	&lt;unix-seconds&gt;", 0 = never).
    /// </summary>
    public DateTime? GetLatestHandshakeUtc()
    {
        var output = RunAndCapture(WgExe, args: ["show", TunnelName, "latest-handshakes"]).Trim();
        var parts = output.Split('	');
        if (parts.Length < 2 || !long.TryParse(parts[1], out var unixSeconds) || unixSeconds <= 0)
            return null;
        return DateTimeOffset.FromUnixTimeSeconds(unixSeconds).UtcDateTime;
    }

    /// <summary>True while the relay has answered within TunnelHealth.StaleAfter.</summary>
    public bool IsHandshakeActive()
    {
        var last = GetLatestHandshakeUtc();
        return last is not null && DateTime.UtcNow - last.Value <= TunnelHealth.StaleAfter;
    }

    /// <summary>
    /// Real received/sent byte counts for the current tunnel, straight from
    /// `wg show securelink transfer` (format: "&lt;peer-pubkey&gt;\t&lt;rx-bytes&gt;\t&lt;tx-bytes&gt;").
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
        // Both output streams are captured on purpose. wireguard.exe reports a failure
        // by writing to its error stream if it has one, and otherwise by opening a
        // modal "Error" message box and waiting for someone to click OK — which froze
        // this app on "Disconnecting..." behind a dialog the user didn't expect. With
        // the streams redirected it never shows that box, and its real reason for
        // failing ends up in our own error message instead.
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            var reason = (stderr.Result + " " + stdout.Result).Trim();
            throw new InvalidOperationException(reason.Length > 0
                ? $"WireGuard reported: {reason}"
                : $"{exe} {args} failed (exit code {process.ExitCode}).");
        }
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
