using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SessionService;

// ── SessionPool ───────────────────────────────────────────────────────────────
// Owns all managed RDSH sessions for the lifetime of the service.
// Sessions are created once at startup and never destroyed until shutdown.
// Only agent + MCP processes inside are recycled on release.

public class SessionPool
{
    private readonly ILogger<SessionPool> _log;
    private readonly IConfiguration _config;

    private readonly List<ManagedSession> _sessions = new();
    private readonly SemaphoreSlim _lock = new(1, 1);

    private int _agentBasePort;
    private int _mcpBasePort;

    public SessionPool(ILogger<SessionPool> log, IConfiguration config)
    {
        _log = log;
        _config = config;
    }

    // ── InitializeAsync ───────────────────────────────────────────────────────

    public async Task InitializeAsync(CancellationToken ct)
    {
        _agentBasePort = _config.GetValue<int>("agent_types:desktop:agent_base_port", 8000);
        _mcpBasePort   = _config.GetValue<int>("agent_types:desktop:mcp_base_port", 5000);

        List<CredentialStore.UserEntry> users;
        try
        {
            users = CredentialStore.GetAllUsers();
        }
        catch (Exception ex)
        {
            _log.LogError("Failed to load credentials: {err}", ex.Message);
            throw;
        }

        int maxSessions = _config.GetValue<int>("server:max_rdp_sessions", users.Count);
        var usersToInit = users.Take(maxSessions).ToList();

        _log.LogInformation("Initializing {n} RDP sessions sequentially...", usersToInit.Count);

        for (int i = 0; i < usersToInit.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var user = usersToInit[i];
            var session = new ManagedSession
            {
                Id        = i + 1,
                Username  = user.userid,
                Domain    = user.domain ?? ".",
                AgentPort = _agentBasePort + i + 1,
                McpPort   = _mcpBasePort   + i + 1,
                State     = SessionState.Creating,
            };

            _sessions.Add(session);
            await InitSessionAsync(session, user.password, ct);
        }
    }

    // ── InitSessionAsync ──────────────────────────────────────────────────────

    private async Task InitSessionAsync(ManagedSession session,
        string password, CancellationToken ct)
    {
        try
        {
            _log.LogInformation(
                "[Session {id}] Creating RDP session for {user} via 127.0.0.{ip}...",
                session.Id, session.Username, session.Id + 1);

            var (winSessionId, holderPid, loopbackIp, rdpFilePath) =
                await Task.Run(() =>
                    ProcessInjector.CreateRdpSession(
                        session.Username, session.Domain, password,
                        sessionIndex: session.Id), ct);

            session.WindowsSessionId = winSessionId;
            session.HolderProcessId  = holderPid;
            session.LoopbackIp       = loopbackIp;
            session.RdpFilePath      = rdpFilePath;
            session.State            = SessionState.Idle;

            _log.LogInformation(
                "[Session {id}] RDP session created — Windows session ID: {wid}, " +
                "mstsc pid: {pid}, loopback: {ip}",
                session.Id, winSessionId, holderPid, loopbackIp);

            await RunProfileWarmupAsync(session, ct);

            session.State = SessionState.Available;
            _log.LogInformation("[Session {id}] Ready (no agent injected yet)", session.Id);
        }
        catch (Exception ex)
        {
            session.State = SessionState.Dead;
            _log.LogError("[Session {id}] Failed to initialize: {err}", session.Id, ex.Message);
        }
    }

    // ── RunProfileWarmupAsync ─────────────────────────────────────────────────

    private async Task RunProfileWarmupAsync(ManagedSession session, CancellationToken ct)
    {
        var warmupApps = _config
            .GetSection("agent_types:desktop:profile_warmup_apps")
            .Get<List<string>>() ?? new();

        if (!warmupApps.Any()) return;

        _log.LogInformation("[Session {id}] Running profile warmup for {n} apps...",
            session.Id, warmupApps.Count);

        foreach (var appPath in warmupApps)
        {
            try
            {
                _log.LogInformation("[Session {id}] Warming up: {app}", session.Id, appPath);
                int pid = ProcessInjector.InjectProcess(session.WindowsSessionId, appPath, null);
                await Task.Delay(5000, ct);
                try { System.Diagnostics.Process.GetProcessById(pid).Kill(); } catch { }
            }
            catch (Exception ex)
            {
                _log.LogWarning("[Session {id}] Warmup failed for {app}: {err}",
                    session.Id, appPath, ex.Message);
            }
        }
    }

    // ── InjectAgentAsync ──────────────────────────────────────────────────────

    public async Task<bool> InjectAgentAsync(int sessionId, InjectRequest req)
    {
        var session = _sessions.FirstOrDefault(s => s.Id == sessionId);
        if (session == null) return false;

        await _lock.WaitAsync();
        try
        {
            if (session.State != SessionState.Available && session.State != SessionState.Idle)
            {
                _log.LogWarning("[Session {id}] Cannot inject — state is {s}",
                    sessionId, session.State);
                return false;
            }
            session.State     = SessionState.Injecting;
            session.AgentType = req.AgentType;
        }
        finally { _lock.Release(); }

        try
        {
            _log.LogInformation(
                "[Session {id}] Injecting {type} — agent:{ap} mcp:{mp}",
                session.Id, req.AgentType, req.AgentPort, req.McpPort);

            int mcpPid = await Task.Run(() =>
                ProcessInjector.InjectProcess(session.WindowsSessionId,
                    req.McpBinary, $"--urls http://localhost:{req.McpPort}"));

            session.McpProcessId = mcpPid;
            _log.LogInformation("[Session {id}] MCP injected (pid {pid})", session.Id, mcpPid);

            await Task.Delay(1000);

            int agentPid = await Task.Run(() =>
                ProcessInjector.InjectProcess(session.WindowsSessionId,
                    req.AgentScript,
                    $"--port {req.AgentPort} --mcp-url http://localhost:{req.McpPort}"));

            session.AgentProcessId = agentPid;
            _log.LogInformation("[Session {id}] Agent injected (pid {pid})", session.Id, agentPid);

            session.State = SessionState.Available;
            return true;
        }
        catch (Exception ex)
        {
            session.State = SessionState.Dead;
            _log.LogError("[Session {id}] Inject failed: {err}", session.Id, ex.Message);
            return false;
        }
    }

    // ── GetAvailableSessionAsync ──────────────────────────────────────────────

    public async Task<ManagedSession?> GetAvailableSessionAsync(string agentType)
    {
        await _lock.WaitAsync();
        try
        {
            var session = _sessions.FirstOrDefault(s =>
                s.State == SessionState.Available &&
                s.AgentType == agentType);

            if (session != null)
            {
                session.State      = SessionState.Busy;
                session.AssignedAt = DateTime.UtcNow;
            }

            return session;
        }
        finally { _lock.Release(); }
    }

    // ── ReleaseSessionAsync ───────────────────────────────────────────────────

    public async Task<bool> ReleaseSessionAsync(int sessionId,
        string agentScript, string mcpBinary)
    {
        var session = _sessions.FirstOrDefault(s => s.Id == sessionId);
        if (session == null) return false;

        _log.LogInformation("[Session {id}] Releasing — killing agent + MCP", sessionId);

        KillProcess(session.AgentProcessId, "agent", sessionId);
        KillProcess(session.McpProcessId,   "mcp",   sessionId);

        session.AgentProcessId = -1;
        session.McpProcessId   = -1;
        session.AssignedTo     = "";
        session.State          = SessionState.Available;

        var req = new InjectRequest(
            session.AgentType, agentScript, mcpBinary,
            session.AgentPort, session.McpPort);

        return await InjectAgentAsync(sessionId, req);
    }

    // ── ShutdownAsync ─────────────────────────────────────────────────────────
    // Called by SessionServiceWorker on service stop.
    // Kills all processes, logs off sessions, cleans up loopback credentials.

    public Task ShutdownAsync()
    {
        _log.LogInformation("SessionPool shutting down — cleaning up {n} sessions...",
            _sessions.Count);

        foreach (var session in _sessions)
        {
            KillProcess(session.AgentProcessId,  "agent",  session.Id);
            KillProcess(session.McpProcessId,    "mcp",    session.Id);
            KillProcess(session.HolderProcessId, "mstsc",  session.Id);

            if (session.WindowsSessionId >= 0)
            {
                try
                {
                    NativeMethods.WTSLogoffSession(
                        IntPtr.Zero, session.WindowsSessionId, false);
                    _log.LogInformation(
                        "[Session {id}] Logged off Windows session {wid}",
                        session.Id, session.WindowsSessionId);
                }
                catch (Exception ex)
                {
                    _log.LogWarning("[Session {id}] WTSLogoffSession failed: {err}",
                        session.Id, ex.Message);
                }
            }

            // Remove .rdp file and credential store entry
            if (!string.IsNullOrEmpty(session.LoopbackIp))
                ProcessInjector.CleanupLoopback(session.LoopbackIp, session.RdpFilePath);
        }

        _log.LogInformation("SessionPool shutdown complete.");
        return Task.CompletedTask;
    }

    // ── GetAllSessions ────────────────────────────────────────────────────────

    public IReadOnlyList<ManagedSession> GetAllSessions() => _sessions.AsReadOnly();

    // ── KillProcess ───────────────────────────────────────────────────────────

    private void KillProcess(int pid, string label, int sessionId)
    {
        if (pid <= 0) return;
        try
        {
            var proc = System.Diagnostics.Process.GetProcessById(pid);
            proc.Kill();
            _log.LogInformation("[Session {id}] Killed {label} (pid {pid})",
                sessionId, label, pid);
        }
        catch (Exception ex)
        {
            _log.LogWarning("[Session {id}] Could not kill {label} (pid {pid}): {err}",
                sessionId, label, pid, ex.Message);
        }
    }
}