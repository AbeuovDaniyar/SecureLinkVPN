using System.Windows;
using System.Windows.Input;
using SecureLink.Client.Services;
using KeyEventArgs = System.Windows.Input.KeyEventArgs;

namespace SecureLink.Client;

public partial class LoginWindow : Window
{
    private readonly ApiClient _api = new(AppConfig.ApiBaseUrl);
    private bool _isRegisterMode;

    public LoginWindow()
    {
        InitializeComponent();
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) => DragMove();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void ToggleMode_Click(object sender, RoutedEventArgs e)
    {
        _isRegisterMode = !_isRegisterMode;

        SubtitleText.Text = _isRegisterMode ? "Create your account" : "Sign in to connect";
        SubmitButton.Content = _isRegisterMode ? "Sign up" : "Log in";
        ToggleModeButton.Content = _isRegisterMode ? "Already have an account? Log in" : "Don't have an account? Sign up";
        ConfirmPasswordPanel.Visibility = _isRegisterMode ? Visibility.Visible : Visibility.Collapsed;
        StatusText.Text = "";
    }

    private async void SubmitButton_Click(object sender, RoutedEventArgs e) => await TrySubmitAsync();

    private async void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            await TrySubmitAsync();
    }

    private async Task TrySubmitAsync()
    {
        var email = EmailBox.Text.Trim();
        var password = PasswordBox.Password;

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            StatusText.Text = "Enter both email and password.";
            return;
        }

        if (_isRegisterMode && password != ConfirmPasswordBox.Password)
        {
            StatusText.Foreground = (System.Windows.Media.Brush)FindResource("ErrorBrush");
            StatusText.Text = "Passwords don't match.";
            return;
        }

        SubmitButton.IsEnabled = false;
        ToggleModeButton.IsEnabled = false;
        StatusText.Text = _isRegisterMode ? "Creating account..." : "Logging in...";
        StatusText.Foreground = (System.Windows.Media.Brush)FindResource("TextSecondaryBrush");

        try
        {
            if (_isRegisterMode)
                await _api.RegisterAsync(email, password);
            else
                await _api.LoginAsync(email, password);

            var main = new MainWindow(_api);
            main.Show();

            // Swap this window out as the application's main window before closing it,
            // so the app doesn't shut down when LoginWindow.Close() runs.
            System.Windows.Application.Current.MainWindow = main;
            Close();
        }
        catch (Exception ex)
        {
            StatusText.Foreground = (System.Windows.Media.Brush)FindResource("ErrorBrush");
            StatusText.Text = _isRegisterMode ? $"Sign up failed: {ex.Message}" : $"Login failed: {ex.Message}";
            SubmitButton.IsEnabled = true;
            ToggleModeButton.IsEnabled = true;
        }
    }
}
