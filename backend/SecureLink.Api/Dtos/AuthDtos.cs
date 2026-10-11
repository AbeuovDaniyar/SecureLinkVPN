namespace SecureLink.Api.Dtos;

// InviteCode is only checked when the server has Registration:InviteCode configured.
public record RegisterRequest(string Email, string Password, string? InviteCode = null);

public record LoginRequest(string Email, string Password);

public record AuthResponse(string Token, DateTime ExpiresAt);
