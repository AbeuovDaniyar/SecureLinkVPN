using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureLink.Api.Data;
using SecureLink.Api.Services;

namespace SecureLink.Api.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Policy = "AdminOnly")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IRelayGatewayService _relayGateway;

    public AdminController(AppDbContext db, IRelayGatewayService relayGateway)
    {
        _db = db;
        _relayGateway = relayGateway;
    }

    [HttpGet("sessions")]
    public async Task<IActionResult> ActiveSessions()
    {
        var sessions = await _db.Sessions
            .Where(s => s.EndedAt == null)
            .Include(s => s.User)
            .Select(s => new
            {
                s.Id,
                UserEmail = s.User!.Email,
                s.Region,
                s.TunnelIp,
                s.StartedAt,
            })
            .ToListAsync();

        return Ok(sessions);
    }

    [HttpPost("sessions/{id}/revoke")]
    public async Task<IActionResult> Revoke(Guid id)
    {
        var session = await _db.Sessions.FirstOrDefaultAsync(s => s.Id == id && s.EndedAt == null);
        if (session is null)
            return NotFound();

        var relay = _relayGateway.GetRelay(session.Region);
        await _relayGateway.RemovePeerAsync(relay, session.ClientPublicKey);
        session.EndedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        return NoContent();
    }
}
