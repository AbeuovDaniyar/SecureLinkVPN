using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureLink.Api.Data;
using SecureLink.Api.Dtos;
using SecureLink.Api.Models;
using SecureLink.Api.Services;

namespace SecureLink.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ITokenService _tokens;
    private readonly IConfiguration _config;

    public AuthController(AppDbContext db, ITokenService tokens, IConfiguration config)
    {
        _db = db;
        _tokens = tokens;
        _config = config;
    }

    // Sign-up is by invitation. The relays are small, privately paid-for servers, and
    // every account can send traffic out through them — so a public download link must
    // not mean that anyone at all can register. When Registration:InviteCode is set,
    // a registration has to present the same code; when it's empty (local development),
    // registration is open.
    private bool InviteCodeAccepted(string? supplied)
    {
        var required = _config["Registration:InviteCode"];
        if (string.IsNullOrEmpty(required))
            return true;

        // Constant-time comparison, so response timing can't be used to guess the code.
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes((supplied ?? string.Empty).Trim()),
            Encoding.UTF8.GetBytes(required));
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest("Email and password are required.");

        if (!InviteCodeAccepted(req.InviteCode))
            return StatusCode(StatusCodes.Status403Forbidden, "A valid invite code is required to sign up.");

        // Emails are compared case-insensitively so "User@x.com" can't register
        // alongside "user@x.com".
        var email = req.Email.Trim();
        if (await _db.Users.AnyAsync(u => u.Email.ToLower() == email.ToLower()))
            return Conflict("An account with that email already exists.");

        var user = new User
        {
            Email = email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
        };

        _db.Users.Add(user);
        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateException)
        {
            // Two simultaneous registrations for the same email both passed the check
            // above; the unique index (IX_Users_Email) rejected the second one.
            return Conflict("An account with that email already exists.");
        }

        var (token, expiresAt) = _tokens.GenerateToken(user);
        return Ok(new AuthResponse(token, expiresAt));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest req)
    {
        var email = req.Email.Trim();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email.ToLower() == email.ToLower());
        if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
            return Unauthorized("Invalid email or password.");

        var (token, expiresAt) = _tokens.GenerateToken(user);
        return Ok(new AuthResponse(token, expiresAt));
    }

    // Swaps the caller's still-valid token for a fresh one. Tokens are short-lived
    // (Jwt:AccessTokenMinutes), so without this a client that stays signed in — or
    // simply stays connected for longer than one token lifetime — would have its
    // later calls (including Disconnect) rejected. An expired or tampered token never
    // reaches this method: [Authorize] answers 401 first. The user is re-read from
    // the database so a deleted account or a changed admin flag takes effect here.
    [Authorize]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        var sub = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized();

        var user = await _db.Users.FindAsync(userId);
        if (user is null)
            return Unauthorized();

        var (token, expiresAt) = _tokens.GenerateToken(user);
        return Ok(new AuthResponse(token, expiresAt));
    }
}
