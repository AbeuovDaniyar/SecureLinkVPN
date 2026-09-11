using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureLink.Api.Data;
using SecureLink.Api.Dtos;
using SecureLink.Api.Models;
using SecureLink.Api.Services;

namespace SecureLink.Api.Controllers;

[ApiController]
[Route("api/sessions")]
[Authorize]
public class SessionsController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IRelayGatewayService _relayGateway;

    public SessionsController(AppDbContext db, IRelayGatewayService relayGateway)
    {
        _db = db;
        _relayGateway = relayGateway;
    }

    private Guid CurrentUserId =>
        Guid.Parse(User.FindFirstValue(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)!);

    [HttpPost("connect")]
    public async Task<IActionResult> Connect(ConnectRequest req)
    {
        // One active session per user at a time — matches FR-3/FR-15 in the SRS.
        var existing = await _db.Sessions
            .Where(s => s.UserId == CurrentUserId && s.EndedAt == null)
            .FirstOrDefaultAsync();
        if (existing is not null)
            return Conflict("You already have an active session. Disconnect first.");

        RelayServer relay;
        try
        {
            relay = _relayGateway.GetRelay(req.Region);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }

        var ipsInUse = await _db.Sessions
            .Where(s => s.Region == relay.Region && s.EndedAt == null)
            .Select(s => s.TunnelIp)
            .ToListAsync();

        var tunnelIp = _relayGateway.AssignTunnelIp(relay, ipsInUse);

        await _relayGateway.AddPeerAsync(relay, req.ClientPublicKey, tunnelIp);

        var session = new Session
        {
            UserId = CurrentUserId,
            Region = relay.Region,
            ClientPublicKey = req.ClientPublicKey,
            TunnelIp = tunnelIp,
        };
        _db.Sessions.Add(session);
        await _db.SaveChangesAsync();

        return Ok(new ConnectResponse(
            SessionId: session.Id,
            RelayPublicKey: relay.PublicKey,
            RelayEndpoint: relay.Endpoint,
            TunnelIp: tunnelIp,
            TunnelSubnet: relay.TunnelSubnet
        ));
    }

    [HttpPost("disconnect")]
    public async Task<IActionResult> Disconnect(DisconnectRequest req)
    {
        var session = await _db.Sessions
            .FirstOrDefaultAsync(s => s.Id == req.SessionId && s.UserId == CurrentUserId);
        if (session is null)
            return NotFound();

        if (session.IsActive)
        {
            var relay = _relayGateway.GetRelay(session.Region);
            await _relayGateway.RemovePeerAsync(relay, session.ClientPublicKey);
            session.EndedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }

        return NoContent();
    }

    [HttpGet("active")]
    public async Task<IActionResult> Active()
    {
        var session = await _db.Sessions
            .Where(s => s.UserId == CurrentUserId && s.EndedAt == null)
            .FirstOrDefaultAsync();

        return session is null ? NoContent() : Ok(session);
    }
}
