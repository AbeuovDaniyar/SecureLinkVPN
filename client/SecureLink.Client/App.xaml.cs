using System.Diagnostics;
using System.Windows;
using SecureLink.Client.Services;

namespace SecureLink.Client;

public partial class App : System.Windows.Application
{
    private const string WireGuardDownloadUrl = "https://www.wireguard.com/install/";

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // SecureLink drives the official WireGuard programs rather than shipping its
        // own copy. Without them nothing can work, and the first sign of trouble would
        // otherwise be a cryptic "file not found" when the user presses Connect — so
        // say exactly what's missing, and where to get it, before anything else.
        if (!WireGuardInterop.IsInstalled)
        {
            var choice = System.Windows.MessageBox.Show(
                "SecureLink needs WireGuard for Windows, and it isn't installed on this PC.\n\n" +
                "Click Yes to open the official WireGuard download page. Install it, then start SecureLink again.",
                "WireGuard isn't installed",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (choice == MessageBoxResult.Yes)
            {
                try { Process.Start(new ProcessStartInfo(WireGuardDownloadUrl) { UseShellExecute = true }); }
                catch (Exception) { /* no browser available; the message above already named what to install */ }
            }

            Shutdown();
            return;
        }

        new LoginWindow().Show();
    }
}
