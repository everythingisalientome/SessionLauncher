# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

Build entire solution:
```bash
dotnet build SessionLauncher.sln -c Release
```

Publish individual projects (self-contained, win-x64):
```bash
dotnet publish SessionLauncher/SessionLauncher.csproj -c Release -r win-x64 --self-contained true -o SessionLauncher/publish
dotnet publish Credtool/Credtool.csproj -c Release -r win-x64 --self-contained true -o Credtool/publish
dotnet publish SessionService/SessionService.csproj -c Release -r win-x64 --self-contained true -o SessionService/publish
```

No tests exist in this repository.

## Architecture

Three .NET 8 Windows projects that collectively manage isolated RDSH (Remote Desktop Session Host) user sessions for running parallel automation agents.

### SessionLauncher (console utility)
Two operational modes, both require running as LocalSystem/admin:
- `--create-session --user <username>`: Creates an isolated interactive RDP session for the given user. Outputs the Windows session ID to stdout.
- `--user <username> --exe <path> --args <args>`: Injects an executable into an existing active session using `WTSQueryUserToken` + `CreateProcessAsUser`.

Exit codes: 0=success, 1=missing args, 2=session not found/Win32 failure, 3=CreateProcessAsUser failed, 4=credential load failure, 5=session creation timeout, 6=no active session.

Logs to `C:\agents\SessionLauncher.log`.

### Credtool (credential manager)
Encrypts/decrypts a `credentials.yaml` file to/from `credentials.enc` using DPAPI (`DataProtectionScope.LocalMachine`, entropy: `"AgentCredentials:SessionLauncher:v1"`). Credentials are machine-bound and non-portable.

Commands: `--encrypt`, `--decrypt`, `--verify`

The encrypted file is read by both SessionLauncher and SessionService. SessionService looks for it at `../SessionLauncher/credentials.enc` relative to its own exe.

### SessionService (Windows service)
HTTP service (default port 9001) that manages a pool of RDSH sessions. Runs as LocalSystem.

**Session lifecycle:** `Creating → Idle → Available → Busy → Available` (after release), fault state: `Dead`

**Loopback RDP strategy:** Each session gets a unique loopback IP (`127.0.0.2`, `127.0.0.3`, ...) to isolate credential storage via `cmdkey /add:TERMSRV/127.0.0.X`. This avoids credential collisions when running multiple sessions from SYSTEM.

**REST API:**
- `GET /sessions/status` — list all sessions
- `GET /sessions/available?type=<type>` — claim an available session
- `POST /sessions/{id}/inject` — inject agent + MCP binaries
- `POST /sessions/{id}/release` — release session and restart agents
- `GET /health`

**Key source files:**
- `Program.cs` — service entry point, HTTP API routing
- `SessionPool.cs` — session lifecycle (create, inject, release, shutdown)
- `ProcessInjector.cs` — loopback RDP creation and process injection via WTS APIs
- `CredentialStore.cs` — decrypts credentials.enc and parses user entries
- `NativeMethods.cs` — P/Invoke for advapi32, wtsapi32, kernel32
- `Models.cs` — `ManagedSession`, `SessionState` enum, API request/response types

Configuration is in `appsettings.json` (`session_service.port`, `server.max_rdp_sessions`, `agent_types.*`).

## Credential Workflow

1. Edit `credentials.yaml` (format: userid/password/domain/name/email per user)
2. Run `CredTool.exe --encrypt` — produces `credentials.enc` and securely wipes the YAML
3. To edit: `CredTool.exe --decrypt`, modify, then `CredTool.exe --encrypt` again

## Service Installation

```powershell
sc.exe create SessionService binPath= "C:\agents\SessionService\SessionService.exe" start= auto obj= LocalSystem
sc.exe start SessionService
```

Verify: `curl http://localhost:9001/health`

## CyberArk Integration

`SessionLauncher/Program.cs` and `SessionService/CredentialStore.cs` contain TODO stubs for replacing DPAPI-encrypted `credentials.enc` with CyberArk vault lookups.
