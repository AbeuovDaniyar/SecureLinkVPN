using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using SecureLink.Client.Services;

namespace SecureLink.Client;

public partial class MainWindow : Window
{
    private enum ConnState { Disconnected, Connecting, Connected }

    private static readonly (string Tag, string Label)[] Regions =
    [
        ("virginia", "🇺🇸 Virginia (US-East)"),
        ("germany", "🇩🇪 Germany (EU-Central)"),
    ];

    private readonly ApiClient _api;
    private readonly WireGuardInterop _wireGuard = new();
    private readonly KillSwitchService _killSwitch = new();
    private readonly DispatcherTimer _statsTimer;

    private Guid? _activeSessionId;
    private bool _connected;
    private int _regionIndex;
    private DateTime _connectedSinceUtc;

    // _api arrives already authenticated — LoginWindow calls ApiClient.LoginAsync
    // (which sets AuthToken) before constructing this window.
    public MainWindow(ApiClient api)
    {
        InitializeComponent();
        _api = api;

        _statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _statsTimer.Tick += StatsTimer_Tick;

        Loaded += async (_, _) => await CleanupOrphanedStateAsync();
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) => DragMove();
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void PrevRegion_Click(object sender, RoutedEventArgs e)
    {
        _regionIndex = (_regionIndex - 1 + Regions.Length) % Regions.Length;
        RegionLabel.Text = Regions[_regionIndex].Label;
    }

    private void NextRegion_Click(object sender, RoutedEventArgs e)
    {
        _regionIndex = (_regionIndex + 1) % Regions.Length;
        RegionLabel.Text = Regions[_regionIndex].Label;
    }

    // Defensive startup check: if a previous run was killed or crashed after
    // BringUpTunnel() installed the tunnel service but before TearDownTunnel() (or
    // ConnectAsync's own rollback) could remove it, that service and its kill switch
    // firewall rules survive independently of this app — silently breaking internet
    // access until someone notices and cleans it up by hand (as happened once
    // already). Check for and clear that out before the user can even hit Connect —
    // both the local artifacts AND the backend session, since closing the local
    // tunnel alone leaves the backend (and the real peer on the relay) thinking
    // you're still connected, which then rejects the next Connect with 409.
    private async Task CleanupOrphanedStateAsync()
    {
        try
        {
            if (await Task.Run(() => _wireGuard.OrphanedTunnelServiceExists()))
            {
                Log("Found a leftover tunnel from a previous session — cleaning it up...");
                await Task.Run(() => _wireGuard.TearDownTunnel());
                Log("Cleaned up leftover tunnel.");
            }
        }
        catch (Exception ex)
        {
            Log($"Warning: found a leftover tunnel but couldn't remove it automatically ({ex.Message}). " +
                "Make sure you're running as Administrator, or remove it manually: " +
                "\"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice securelink");
        }

        // Safe to call even if no rules exist — KillSwitchService.Disable() no-ops
        // when there's nothing to remove.
        await Task.Run(() => _killSwitch.Disable());

        try
        {
            var staleSessionId = await _api.GetActiveSessionIdAsync();
            if (staleSessionId is Guid sid)
            {
                Log("Found a leftover active session on the server from last time — closing it out...");
                await _api.DisconnectAsync(sid);
                Log("Closed leftover session. Ready to connect.");
            }
        }
        catch (Exception ex)
        {
            Log($"Warning: couldn't check for a leftover server-side session ({ex.Message}). " +
                "If Connect fails with 409, disconnect manually via Swagger/Postman first.");
        }
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_connected)
        {
            await DisconnectAsync();
            return;
        }

        await ConnectAsync();
    }

    private async Task ConnectAsync()
    {
        Guid? sessionId = null;
        var tunnelUp = false;
        var killSwitchUp = false;

        try
        {
            SetUiState(ConnState.Connecting);

            var (regionTag, regionLabel) = Regions[_regionIndex];

            var (privateKey, publicKey) = await Task.Run(() => _wireGuard.GenerateKeyPair());

            var result = await _api.ConnectAsync(regionTag, publicKey);
            sessionId = result.SessionId;

            await Task.Run(() => _wireGuard.BringUpTunnel(
                privateKey: privateKey,
                localAddress: result.TunnelIp,
                relayPublicKey: result.RelayPublicKey,
                relayEndpoint: result.RelayEndpoint
            ));
            tunnelUp = true;

            await Task.Run(() => _killSwitch.Enable(result.RelayEndpoint, result.TunnelIp));
            killSwitchUp = true;

            _activeSessionId = result.SessionId;
            _connected = true;
            SetUiState(ConnState.Connected, regionLabel);
            Log($"Tunnel up. Local IP {result.TunnelIp} via {result.RelayEndpoint}.");
        }
        catch (Exception ex)
        {
            // Never leave a half-up tunnel or kill switch behind just because the UI
            // never made it to "Connected" — that's exactly how you end up with a live
            // full-tunnel WireGuard service (AllowedIPs = 0.0.0.0/0, i.e. it owns your
            // default route) and no way online, with the app innocently showing
            // "Disconnected". Roll back everything that did succeed before failing.
            var cleanupErrors = new List<string>();

            if (killSwitchUp)
            {
                try { await Task.Run(() => _killSwitch.Disable()); }
                catch (Exception cleanupEx) { cleanupErrors.Add($"kill switch: {cleanupEx.Message}"); }
            }
            if (tunnelUp)
            {
                try { await Task.Run(() => _wireGuard.TearDownTunnel()); }
                catch (Exception cleanupEx) { cleanupErrors.Add($"tunnel: {cleanupEx.Message}"); }
            }
            if (sessionId is Guid sid)
            {
                try { await _api.DisconnectAsync(sid); }
                catch (Exception cleanupEx) { cleanupErrors.Add($"backend session: {cleanupEx.Message}"); }
            }

            _connected = false;
            _activeSessionId = null;
            SetUiState(ConnState.Disconnected);

            Log(cleanupErrors.Count == 0
                ? $"Connect failed: {ex.Message}"
                : $"Connect failed: {ex.Message} — ALSO FAILED TO CLEAN UP ({string.Join("; ", cleanupErrors)}). Check `wg show` and Windows Firewall manually.");
        }
    }

    private async Task DisconnectAsync()
    {
        // Local teardown must happen no matter what the backend says. If the relay's
        // management API is briefly unreachable (dropped SSH tunnel, relay hiccup,
        // ...) the backend call below can fail — but that must never trap the user in
        // a full-tunnel state with no way back to the internet just because a remote
        // service didn't answer. Restoring this machine's own connectivity always
        // takes priority; the backend session can be reconciled later (the next
        // launch's CleanupOrphanedStateAsync will pick it up, or it can be closed
        // manually via Swagger/Postman).
        SetUiState(ConnState.Connecting); // reuse the busy/loading look while tearing down
        StatusText.Text = "Disconnecting...";

        // Local teardown goes FIRST and unconditionally, before the backend is even
        // contacted. The backend call is a network request that can be slow (this
        // specific link has been observed needing multiple TLS renegotiations) or
        // outright hang up to HttpClient's default 100s timeout — and every second of
        // that is a second the kill switch is still fully blocking outbound traffic
        // with no way for the user to get their own internet back. Restoring local
        // connectivity can never wait on a remote call's timing.
        var localErrors = new List<string>();
        try { await Task.Run(() => _wireGuard.TearDownTunnel()); }
        catch (Exception ex) { localErrors.Add($"tunnel: {ex.Message}"); }

        try { await Task.Run(() => _killSwitch.Disable()); }
        catch (Exception ex) { localErrors.Add($"kill switch: {ex.Message}"); }

        string? backendError = null;
        if (_activeSessionId is Guid sessionId)
        {
            // A single transient network blip here has an outsized consequence: the
            // backend session gets stuck "active" and every future Connect 409s until
            // the app is restarted (which reconciles it) or it's closed manually. Retry
            // a couple of times before giving up and falling back to that recovery path.
            // ApiClient bounds each attempt to a short timeout, so this can't hang the
            // UI — local connectivity is already restored above regardless.
            const int maxAttempts = 3;
            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    await _api.DisconnectAsync(sessionId);
                    backendError = null;
                    break;
                }
                catch (Exception ex)
                {
                    backendError = ex.Message;
                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(1.5 * attempt));
                }
            }
        }

        _connected = false;
        _activeSessionId = null;
        SetUiState(ConnState.Disconnected);

        if (backendError is null && localErrors.Count == 0)
        {
            Log("Tunnel down.");
        }
        else
        {
            var parts = new List<string>();
            if (backendError is not null) parts.Add($"backend: {backendError}");
            parts.AddRange(localErrors);

            Log(localErrors.Count == 0
                ? $"Disconnected locally, but the backend wasn't reachable ({backendError}) — its session record may still show active until reconciled."
                : $"Disconnected, but with problems ({string.Join("; ", parts)}). Check `wg show securelink` and Windows Firewall manually.");
        }
    }

    private void StatsTimer_Tick(object? sender, EventArgs e)
    {
        var elapsed = DateTime.UtcNow - _connectedSinceUtc;
        DurationText.Text = $"{(int)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}";

        try
        {
            var (rx, tx) = _wireGuard.GetTransferStats();
            DownloadedText.Text = FormatBytes(rx);
            UploadedText.Text = FormatBytes(tx);
        }
        catch
        {
            // Tunnel may be mid-teardown or briefly unavailable — just skip this tick
            // rather than spamming the log with a transient stats-read failure.
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double size = bytes;
        var unitIndex = 0;
        while (size >= 1024 && unitIndex < units.Length - 1)
        {
            size /= 1024;
            unitIndex++;
        }
        return $"{size:0.##} {units[unitIndex]}";
    }

    private void SetUiState(ConnState state, string? regionLabel = null)
    {
        var spin = (Storyboard)Resources["SpinStoryboard"];
        var pulse = (Storyboard)Resources["PulseStoryboard"];
        var accent = (System.Windows.Media.Brush)FindResource("AccentBrush");
        var muted = (System.Windows.Media.Brush)FindResource("MutedBrush");

        switch (state)
        {
            case ConnState.Disconnected:
                StatusText.Text = "Disconnected";
                StatusText.Foreground = muted;
                SpinnerRing.Visibility = Visibility.Collapsed;
                ConnectedRing.Visibility = Visibility.Collapsed;
                PowerIcon.Foreground = muted;
                spin.Stop(this);
                pulse.Stop(this);
                GlowEllipse.Opacity = 0;
                PrevRegionButton.IsEnabled = true;
                NextRegionButton.IsEnabled = true;
                ConnectButton.IsEnabled = true;
                _statsTimer.Stop();
                DownloadedText.Text = "0 B";
                UploadedText.Text = "0 B";
                DurationText.Text = "00:00:00";
                break;

            case ConnState.Connecting:
                StatusText.Text = "Connecting...";
                StatusText.Foreground = accent;
                SpinnerRing.Visibility = Visibility.Visible;
                ConnectedRing.Visibility = Visibility.Collapsed;
                PowerIcon.Foreground = accent;
                spin.Begin(this, true);
                pulse.Begin(this, true);
                PrevRegionButton.IsEnabled = false;
                NextRegionButton.IsEnabled = false;
                ConnectButton.IsEnabled = false;
                _statsTimer.Stop();
                break;

            case ConnState.Connected:
                StatusText.Text = $"Connected — {regionLabel}";
                StatusText.Foreground = accent;
                SpinnerRing.Visibility = Visibility.Collapsed;
                ConnectedRing.Visibility = Visibility.Visible;
                PowerIcon.Foreground = accent;
                spin.Stop(this);
                pulse.Stop(this);
                GlowEllipse.Opacity = 0.85;
                PrevRegionButton.IsEnabled = false;
                NextRegionButton.IsEnabled = false;
                ConnectButton.IsEnabled = true;
                _connectedSinceUtc = DateTime.UtcNow;
                _statsTimer.Start();
                break;
        }
    }

    private void Log(string message) => LogText.Text = message;
}
