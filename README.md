# SessionLauncher

A .NET 8 Windows console utility that launches executables inside specific Windows RDSH (Remote Desktop Session Host) user sessions. Used by the registry to run desktop agents and MCP tools in isolated user sessions for parallel automation.

---

## Project Structure

```
SessionLauncher/
├── SessionLauncher.csproj      # .NET 8 Windows console project
├── Program.cs                  # Entry point — session lookup + process launch
└── publish/                    # Self-contained build output
    └── SessionLauncher.exe
```

---

## How It Works

1. Accepts `--user`, `--exe`, and `--args` as command line arguments
2. Calls `WTSEnumerateSessions` to list all active Windows sessions
3. Matches the session belonging to the target username via `WTSQuerySessionInformation`
4. Gets the user token for that session via `WTSQueryUserToken`
5. Launches the executable inside that session via `CreateProcessAsUser`

This ensures each process runs in its own isolated Windows desktop session — Notepad and other UI automation happens invisibly inside that user's session, not the admin session.

Logs to: `C:\agents\SessionLauncher\launcher.log`

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Missing `--user` or `--exe` argument |
| 2 | No active session found for the specified user |
| 3 | `CreateProcessAsUser` failed |

---

## Win32 APIs Used

| API | Purpose |
|---|---|
| `WTSEnumerateSessions` | List all active Windows sessions |
| `WTSQuerySessionInformation` | Get username for a session |
| `WTSQueryUserToken` | Get impersonation token for a session |
| `CreateProcessAsUser` | Launch process in the target session |
| `ShowWindow` / `SetForegroundWindow` | (referenced for context) |

---

## Build

```bash
cd D:\VisualStudioWrkSpce\2022\SessionLauncher\SessionLauncher

dotnet publish -c Release -r win-x64 --self-contained true -o ./publish
```

Output: `./publish/SessionLauncher.exe`

> Requires `net8.0-windows` target framework.

---

## Run

```bash
# Launch an exe in a specific user session
SessionLauncher.exe --user agent_user_1 --exe "C:\agents\desktop_agent\desktop_agent.exe" --args "--port 8001 --mcp-url http://localhost:5001"

# Launch MCP tool in a specific user session
SessionLauncher.exe --user agent_user_1 --exe "C:\agents\GoogleSearchMcp\GoogleSearchMcp.exe" --args "--urls http://localhost:5001"
```

> **Prerequisite:** The target user must have an active RDP session on the machine. If the session is not active, exit code 2 is returned.

---

## Deploy to Server

Copy entire `publish\` folder to:
```
C:\agents\SessionLauncher\
```

Create the log directory:
```powershell
New-Item -ItemType Directory -Force -Path C:\agents\SessionLauncher
```

---

## Prerequisites on Server

1. Windows Server 2022 with RDSH role enabled
2. Users `agent_user_1`, `agent_user_2`, `agent_user_3` created and added to Remote Desktop Users group
3. All 3 users must have active RDP sessions before the registry starts
4. Registry must run as Administrator (required for `WTSQueryUserToken`)

---

## Verify Active Sessions

```powershell
query session
```

Expected output:
```
 SESSIONNAME       USERNAME          ID  STATE
 rdp-tcp#0         agent_user_1       2  Active
 rdp-tcp#1         agent_user_2       3  Active
 rdp-tcp#2         agent_user_3       4  Active
```