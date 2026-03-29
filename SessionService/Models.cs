namespace SessionService;

// ── Session states ────────────────────────────────────────────────────────────

public enum SessionState
{
    Creating,    // RDP session being established
    Idle,        // Session alive, no agent injected
    Injecting,   // Agent + MCP being injected
    Available,   // Agent + MCP running, ready to assign
    Busy,        // Assigned to a caller
    Dead,        // Session lost — needs recovery
}

// ── A single managed session ──────────────────────────────────────────────────

public class ManagedSession
{
    public int Id { get; init; }
    public string Username { get; init; } = "";
    public string Domain { get; init; } = ".";
    public string AgentType { get; set; } = "";

    public int WindowsSessionId { get; set; } = -1;
    public int AgentPort { get; set; }
    public int McpPort { get; set; }

    public SessionState State { get; set; } = SessionState.Creating;

    // Loopback RDP tracking
    // Each session gets a unique loopback IP (127.0.0.2, 127.0.0.3, ...)
    // so credential store entries never collide.
    public string LoopbackIp { get; set; } = "";
    public string RdpFilePath { get; set; } = "";

    // HolderProcessId — the mstsc.exe process keeping the session alive.
    // Killed on service shutdown before WTSLogoffSession is called.
    public int HolderProcessId { get; set; } = -1;

    public int AgentProcessId { get; set; } = -1;
    public int McpProcessId { get; set; } = -1;

    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime AssignedAt { get; set; }
    public string AssignedTo { get; set; } = "";

    public object ToDict() => new
    {
        id = Id,
        username = Username,
        agent_type = AgentType,
        windows_session = WindowsSessionId,
        agent_port = AgentPort,
        mcp_port = McpPort,
        state = State.ToString(),
        loopback_ip = LoopbackIp,
        holder_pid = HolderProcessId,
        agent_pid = AgentProcessId,
        mcp_pid = McpProcessId,
        created_at = CreatedAt,
        assigned_at = AssignedAt,
        assigned_to = AssignedTo,
    };
}

// ── API request/response models ───────────────────────────────────────────────

public record InjectRequest(
    string AgentType,
    string AgentScript,
    string McpBinary,
    int AgentPort,
    int McpPort
);

public record AssignResponse(
    int SessionId,
    string Host,
    int AgentPort,
    int McpPort,
    int WindowsSessionId
);