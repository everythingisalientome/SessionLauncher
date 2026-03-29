using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SessionService;

// ── Program ───────────────────────────────────────────────────────────────────
// SessionService — Windows Service that owns the session pool.
// Exposes a local HTTP API on localhost:9001 for the Registry to call.
//
// Install:  sc.exe create SessionService binPath= "C:\agents\SessionService\SessionService.exe" start= auto obj= LocalSystem
// Start:    sc.exe start SessionService
// Stop:     sc.exe stop SessionService
// Remove:   sc.exe delete SessionService
//
// Runs as: LocalSystem (required for LogonUserW + CreateProcessAsUser)

var builder = WebApplication.CreateBuilder(args);

// ── Windows Service support ───────────────────────────────────────────────────
builder.Host.UseWindowsService(options =>
{
    options.ServiceName = "SessionService";
});

// ── Configuration ─────────────────────────────────────────────────────────────
builder.Configuration
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

// ── Logging ───────────────────────────────────────────────────────────────────
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddEventLog(settings =>
{
    settings.SourceName = "SessionService";
});
builder.Logging.AddFile(Path.Combine(@"C:\agents", "SessionService.log"));

// ── Services ──────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<SessionPool>();
builder.Services.AddHostedService<SessionServiceWorker>();

var app = builder.Build();

// ── HTTP API ──────────────────────────────────────────────────────────────────

var port = builder.Configuration.GetValue<int>("session_service:port", 9001);
app.Urls.Add($"http://localhost:{port}");

// GET /sessions/status
app.MapGet("/sessions/status", (SessionPool pool) =>
{
    var sessions = pool.GetAllSessions().Select(s => s.ToDict());
    return Results.Ok(sessions);
});

// GET /sessions/available?type=desktop
app.MapGet("/sessions/available", async (string type, SessionPool pool) =>
{
    var session = await pool.GetAvailableSessionAsync(type);
    if (session == null)
        return Results.Problem("No available sessions for type: " + type, statusCode: 503);

    var host = builder.Configuration["registry:host"] ?? "localhost";

    return Results.Ok(new AssignResponse(
        session.Id,
        host,
        session.AgentPort,
        session.McpPort,
        session.WindowsSessionId
    ));
});

// POST /sessions/{id}/inject
app.MapPost("/sessions/{id:int}/inject", async (int id, InjectRequest req, SessionPool pool) =>
{
    bool ok = await pool.InjectAgentAsync(id, req);
    return ok ? Results.Ok() : Results.Problem($"Failed to inject into session {id}", statusCode: 500);
});

// POST /sessions/{id}/release
app.MapPost("/sessions/{id:int}/release", async (
    int id,
    SessionPool pool,
    IConfiguration config) =>
{
    string agentScript = config["agent_types:desktop:agent_script"]
        ?? throw new InvalidOperationException("agent_script not configured");
    string mcpBinary = config["agent_types:desktop:mcp_binary"]
        ?? throw new InvalidOperationException("mcp_binary not configured");

    bool ok = await pool.ReleaseSessionAsync(id, agentScript, mcpBinary);
    return ok ? Results.Ok() : Results.Problem($"Failed to release session {id}", statusCode: 500);
});

// GET /health
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.Run();

// ── SessionServiceWorker ──────────────────────────────────────────────────────
// Initializes the session pool at startup.
// Calls ShutdownAsync on stop to kill all processes and log off all sessions.

public class SessionServiceWorker : BackgroundService
{
    private readonly SessionPool _pool;
    private readonly ILogger<SessionServiceWorker> _log;
    private readonly IConfiguration _config;

    public SessionServiceWorker(SessionPool pool,
        ILogger<SessionServiceWorker> log, IConfiguration config)
    {
        _pool   = pool;
        _log    = log;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation("SessionService starting — initializing session pool...");

        try
        {
            await _pool.InitializeAsync(ct);
            _log.LogInformation("SessionService ready.");
        }
        catch (Exception ex)
        {
            _log.LogError("SessionService failed to initialize: {err}", ex.Message);
            throw;
        }

        try
        {
            // Run until cancellation (sc stop / service shutdown)
            await Task.Delay(Timeout.Infinite, ct);
        }
        catch (OperationCanceledException)
        {
            // Expected on service stop — fall through to shutdown
        }
        finally
        {
            _log.LogInformation("SessionService stopping — shutting down session pool...");
            await _pool.ShutdownAsync();
        }
    }
}