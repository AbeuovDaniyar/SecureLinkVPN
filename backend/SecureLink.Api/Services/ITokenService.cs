using SecureLink.Api.Models;

namespace SecureLink.Api.Services;

public interface ITokenService
{
    (string token, DateTime expiresAt) GenerateToken(User user);
}
