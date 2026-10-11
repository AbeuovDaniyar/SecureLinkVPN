# SecureLink

A Windows VPN client built on WireGuard, with an ASP.NET Core backend and two globally distributed relay servers. Built as a senior capstone project (BS Computer Programming).

## What it does

- **Desktop Client (WPF):** Establishes a WireGuard tunnel to a relay of your choice (US-East or Germany) with an integrated kill switch that blocks unencrypted outbound traffic while connected. Stays signed in between launches using Windows Credential Manager, and warns you if the relay stops responding.
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

### Download (easiest)

1. Download the latest `SecureLink-Client-…-win-x64.zip` from the [Releases page](https://github.com/AbeuovDaniyar/SecureLinkVPN/releases) and unzip it.
2. Install [WireGuard for Windows](https://www.wireguard.com/install/) if you don't have it. (If it's missing, SecureLink tells you and opens the download page.)
3. Double-click `SecureLink.Client.exe` and accept the Windows administrator prompt.

Notes:

- **No .NET install needed** — the download includes it.
- **Windows 10/11, 64-bit.**
- **"Windows protected your PC"** may appear the first time, because the app isn't code-signed. Click **More info → Run anyway**.
- **Administrator rights** are required because the app creates a network tunnel and changes Windows Firewall rules. The app asks for them itself.

### Usage

1. Sign in, or choose **Sign up**. Signing up needs an **invite code** — the relays are small private servers, so accounts are by invitation.
2. Select a server location (New York / Germany).
3. Click the power button to connect.
4. Watch the session time and data usage in the window. If the relay ever stops responding, the status changes to **Connection lost**.

You stay signed in between launches (the sign-in token is kept in Windows Credential Manager). Use **Sign out** in the title bar to forget it.

### Build from source

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) and WireGuard for Windows.

```bash
git clone https://github.com/AbeuovDaniyar/SecureLinkVPN.git
cd SecureLinkVPN/client/SecureLink.Client
dotnet build -c Release
bin\Release\net8.0-windows\SecureLink.Client.exe
```

## Self-Hosting & Deployment

To deploy your own backend infrastructure:

1. **Infrastructure:** Provision relay nodes using the Terraform files in `infra/`.
2. **Database & API:** Configure PostgreSQL and launch the API service located in `backend/SecureLink.Api/`. Set `Registration:InviteCode` in the API's configuration to require an invite code at sign-up (leave it empty for open registration).
3. **Client Configuration:** Update `AppConfig.cs` in the client directory with your backend endpoint and SSL certificate details.

## Technical Specifications

- **Client:** C#, WPF, .NET 8
- **Backend:** ASP.NET Core, Entity Framework Core, PostgreSQL
- **Tunneling:** WireGuard CLI / Windows Service Integration
- **Infrastructure:** Terraform, DigitalOcean Droplets, Linux (`ufw`, systemd)