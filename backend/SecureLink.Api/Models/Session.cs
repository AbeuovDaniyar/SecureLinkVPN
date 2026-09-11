namespace SecureLink.Api.Models;

public class Session
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    public string Region { get; set; } = string.Empty;       // "virginia" | "germany"
    public string ClientPublicKey { get; set; } = string.Empty;
    public string TunnelIp { get; set; } = string.Empty;      // e.g. "10.8.0.5/32"

    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime? EndedAt { get; set; }

    public bool IsActive => EndedAt == null;
}
