namespace SecureLink.Api.Services;

// Thrown when a relay's peer-management API can't be reached or refuses a request
// (SSH tunnel down, relay rebooting, timeout, ...). Controllers map this to 502 so
// the client gets a clear message instead of a bare 500 or a long hang.
public class RelayUnavailableException : Exception
{
    public RelayUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}
