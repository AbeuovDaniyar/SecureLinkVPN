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

        if (await _db.Users.AnyAsync(u => u.Email == req.Email))
            return Conflict("An account with that email already exists.");

        var user = new User
        {
            Email = req.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        var (token, expiresAt) = _tokens.GenerateToken(user);
        return Ok(new AuthResponse(token, expiresAt));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest req)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == req.Email);
        if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
            return Unauthorized("Invalid email or password.");

        var (token, expiresAt) = _tokens.GenerateToken(user);
        return Ok(new AuthResponse(token, expiresAt));
    }
}
