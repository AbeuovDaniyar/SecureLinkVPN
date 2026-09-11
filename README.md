# SecureLink

A Windows VPN client built on WireGuard, with an ASP.NET Core backend and two globally distributed relay servers. Built as a senior capstone project (BS Computer Programming).

## What it does

- **Desktop Client (WPF):** Establishes a WireGuard tunnel to a relay of your choice (US-East or Germany) with an integrated kill switch that blocks unencrypted outbound traffic while connected.
- **Backend API:** Manages user authentication (JWT), enforces single-session limits per account, and handles WireGuard peer setup across relay nodes. The client handles key generation locally; private keys are never transmitted to the server.
- **Relay Infrastructure:** Two DigitalOcean droplets (`nyc3` in US-East and `fra1` in Germany) handle traffic routing.

## Architecture

```text
  SecureLink Client (WPF, Windows)
              │
              │  HTTPS, JWT auth
              ▼
  Backend API (ASP.NET Core + PostgreSQL)
   — hosted on the US relay node
              │
              │  peer provisioning
              │  (localhost for US, SSH tunnel for Germany)
      ┌───────┴────────┐
      ▼                ▼
  Relay: US        Relay: Germany
  (nyc3)           (fra1)
      │                │
      └── WireGuard tunnel (UDP, encrypted) ── routed traffic
```

## Project Structure

```text
backend/SecureLink.Api/      ASP.NET Core Web API (auth, sessions, relay orchestration)
client/SecureLink.Client/    WPF Windows client application
infra/                       Terraform configurations for DigitalOcean relays
relay-scripts/               Integration scripts for relay management
docs/                        Design documentation (project proposal, SRS, SDD)
```

## Quick Start — Running the Client

### Prerequisites

- Windows 10/11 (64-bit)
- [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)
- [WireGuard for Windows](https://www.wireguard.com/install/)
- Administrator privileges (required for interface management and firewall rules)

### Build and Run

1. Clone the repository:
   ```bash
   git clone https://github.com/AbeuovDaniyar/SecureLinkVPN.git
   cd SecureLinkVPN/client/SecureLink.Client
   ```

2. Build the project:
   ```bash
   dotnet build -c Release
   ```

3. Launch the executable as Administrator:
   ```cmd
   bin\Release\net8.0-windows\SecureLink.Client.exe
   ```

### Usage

1. Open the application and register a new account or sign in.
2. Select a server location (US / Germany).
3. Click the connect button to establish the WireGuard tunnel.
4. Monitor connection statistics and active session metrics directly from the UI.

## Self-Hosting & Deployment

To deploy your own backend infrastructure:

1. **Infrastructure:** Provision relay nodes using the Terraform files in `infra/`.
2. **Database & API:** Configure PostgreSQL and launch the API service located in `backend/SecureLink.Api/`.
3. **Client Configuration:** Update `AppConfig.cs` in the client directory with your backend endpoint and SSL certificate details.

## Technical Specifications

- **Client:** C#, WPF, .NET 8
- **Backend:** ASP.NET Core, Entity Framework Core, PostgreSQL
- **Tunneling:** WireGuard CLI / Windows Service Integration
- **Infrastructure:** Terraform, DigitalOcean Droplets, Linux (`ufw`, systemd)