using System.Net.Http.Json;
using SecureLink.Api.Models;

namespace SecureLink.Api.Services;

public class RelayGatewayService : IRelayGatewayService
{
    private readonly IReadOnlyList<RelayServer> _relays;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<RelayGatewayService> _logger;

    public RelayGatewayService(
        IReadOnlyList<RelayServer> relays,
        IHttpClientFactory httpClientFactory,
        ILogger<RelayGatewayService> logger)
    {
        _relays = relays;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public RelayServer GetRelay(string region)
    {
        var relay = _relays.FirstOrDefault(r => r.Region.Equals(region, StringComparison.OrdinalIgnoreCase));
        if (relay is null)
            throw new ArgumentException($"Unknown region '{region}'. Valid regions: {string.Join(", ", _relays.Select(r => r.Region))}");
        return relay;
    }

    public string AssignTunnelIp(RelayServer relay, IEnumerable<string> ipsAlreadyInUse)
    {
        // TunnelSubnet looks like "10.8.0.0/24" -> base "10.8.0"
        var baseAddr = relay.TunnelSubnet.Split('/')[0];
        var parts = baseAddr.Split('.');
        var prefix = $"{parts[0]}.{parts[1]}.{parts[2]}";

        var used = new HashSet<string>(ipsAlreadyInUse);
        // .1 is the relay itself; hand out .2 - .254 to clients.
        for (var host = 2; host < 255; host++)
        {
            var candidate = $"{prefix}.{host}/32";
            if (!used.Contains(candidate))
                return candidate;
        }

        throw new InvalidOperationException($"No free tunnel IPs left in {relay.TunnelSubnet} for region {relay.Region}.");
    }

    public async Task AddPeerAsync(RelayServer relay, string clientPublicKey, string allowedIp)
    {
        var client = _httpClientFactory.CreateClient();
        client.BaseAddress = new Uri(relay.ManagementUrl);
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", relay.ManagementToken);

        var response = await client.PostAsJsonAsync("/peers", new
        {
            publicKey = clientPublicKey,
            allowedIp = allowedIp,
        });

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            _logger.LogError("Failed to add peer on relay {Region}: {Status} {Body}", relay.Region, response.StatusCode, body);
            throw new InvalidOperationException($"Relay {relay.Region} rejected peer add: {response.StatusCode}");
        }
    }

    public async Task RemovePeerAsync(RelayServer relay, string clientPublicKey)
    {
        try
        {
            var client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(relay.ManagementUrl);
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", relay.ManagementToken);

            // POST with the key in the JSON body, not DELETE /peers/{key} -- WireGuard
            // public keys are base64 and often contain a literal '/', which breaks the
            // relay's path-based route matching (roughly half of all keys 404).
            var response = await client.PostAsJsonAsync("/peers/remove", new { publicKey = clientPublicKey });

            if (!response.IsSuccessStatusCode)
            {
                // Log but don't throw — disconnect should still succeed locally even if
                // the relay is briefly unreachable;
                _logger.LogWarning("Failed to remove peer on relay {Region}: {Status}", relay.Region, response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            // The status-code check above only covers a response we actually got back.
            // If the relay's management API is unreachable at all (SSH tunnel dropped,
            // relay briefly down, DNS hiccup, ...), DeleteAsync throws before we ever
            // see a response — and that must not stop the caller from ending the
            // session locally. Otherwise a single dropped tunnel means the client can
            // never disconnect (backend 500s forever) and stays fully tunneled with no
            // way out, which is exactly the failure mode this method's callers rely on
            // it not producing.
            _logger.LogWarning(ex, "Could not reach relay {Region} to remove peer — session will still be closed locally.", relay.Region);
        }
    }
}
