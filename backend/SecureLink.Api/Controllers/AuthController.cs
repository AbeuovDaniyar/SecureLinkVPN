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

    public AuthController(AppDbContext db, ITokenService tokens)
    {
        _db = db;
        _tokens = tokens;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest("Email and password are required.");

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
}
