namespace SecureLink.Api.Dtos;

public record ConnectRequest(string Region, string ClientPublicKey);

public record ConnectResponse(
    Guid SessionId,
    string RelayPublicKey,
    string RelayEndpoint,
    string TunnelIp,
    string TunnelSubnet
);

public record DisconnectRequest(Guid SessionId);
