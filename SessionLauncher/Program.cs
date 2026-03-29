using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// ── Logging ───────────────────────────────────────────────────────────────────

const string LogFile = @"C:\agents\SessionLauncher.log";

static void Log(string message)
{
    try { File.AppendAllText(LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}"); } catch { }
    Console.WriteLine(message);
}

// ── Entry point ───────────────────────────────────────────────────────────────
//
// Mode 1 — Create isolated interactive session for a user:
//   SessionLauncher.exe --create-session --user agent_user_1
//   Prints session ID to stdout. Blocks until session is Active (max 30s).
//
// Mode 2 — Inject process into an existing active session:
//   SessionLauncher.exe --user agent_user_1 --exe "C:\..." --args "--port 8001"

bool createSession = args.Contains("--create-session");
string? targetUser = null;
string? exePath    = null;
string? exeArgs    = null;

for (int i = 0; i < args.Length; i++)
{
    if      (args[i] == "--user" && i + 1 < args.Length) targetUser = args[++i];
    else if (args[i] == "--exe"  && i + 1 < args.Length) exePath    = args[++i];
    else if (args[i] == "--args" && i + 1 < args.Length) exeArgs    = args[++i];
}

if (targetUser == null)
{
    Log("Error: --user is required");
    Console.Error.WriteLine("Usage:");
    Console.Error.WriteLine("  SessionLauncher.exe --create-session --user <username>");
    Console.Error.WriteLine("  SessionLauncher.exe --user <username> --exe <path> [--args <args>]");
    return 1;
}

// ── Load credentials ──────────────────────────────────────────────────────────

string password;
string domain;

try
{
    // ── CyberArk placeholder ──────────────────────────────────────────────────
    // TODO: Replace CredentialStore.GetPassword() with CyberArk SDK call:
    //
    //   var cyberArk = new CyberArkClient(vaultAddress, appId, safe, objectName);
    //   var creds = await cyberArk.GetCredentialAsync(targetUser);
    //   password = creds.Password;
    //   domain   = creds.Domain;
    //
    // ─────────────────────────────────────────────────────────────────────────
    var creds = CredentialStore.GetPassword(targetUser);
    password = creds.Password;
    domain   = creds.Domain;
    Log($"Credentials loaded for user: {targetUser}");
}
catch (Exception ex)
{
    Log($"Error loading credentials for {targetUser}: {ex.Message}");
    return 4;
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

if (createSession)
{
    Log($"--create-session mode for user: {targetUser}");
    return CreateUserSession(targetUser, domain, password);
}
else
{
    if (exePath == null)
    {
        Log("Error: --exe is required in inject mode");
        return 1;
    }
    Log($"--inject mode: user:{targetUser} exe:{exePath} args:{exeArgs}");
    return InjectProcess(targetUser, exePath, exeArgs);
}

// ── Mode 1: CreateUserSession ─────────────────────────────────────────────────
// Creates a fresh isolated interactive Windows session for the user.
// Steps:
//   1. LogonUserW to get a user token
//   2. Launch cmd.exe /c exit as that user — forces Windows to create the
//      user profile and register a session entry in the WTS session table
//   3. Poll WTSEnumerateSessionsW until the session appears (Disconnected)
//   4. WTSConnectSession to promote it to Active
//   5. Print session ID to stdout for session_manager.py to capture

static int CreateUserSession(string username, string domain, string password)
{
    // Step 1 — Logon to get user token
    Log($"Logging on user {username}...");
    if (!NativeMethods.LogonUserW(username, domain, password,
            NativeMethods.LOGON32_LOGON_INTERACTIVE,
            NativeMethods.LOGON32_PROVIDER_DEFAULT,
            out IntPtr hToken))
    {
        Log($"LogonUserW failed: {Marshal.GetLastWin32Error()}");
        return 2;
    }

    try
    {
        // Step 2 — Launch cmd /c exit as the user to create profile + session entry
        Log("Launching bootstrap process to create user session...");

        if (!NativeMethods.DuplicateTokenEx(hToken,
                NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                NativeMethods.TOKEN_TYPE.TokenPrimary,
                out IntPtr hPrimaryToken))
        {
            Log($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");
            return 2;
        }

        try
        {
            var si = new NativeMethods.STARTUPINFO
            {
                cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>(),
                lpDesktop = "winsta0\\default"
            };

            string cmdLine = "cmd.exe /c exit";

            if (!NativeMethods.CreateProcessAsUser(
                    hPrimaryToken, null, cmdLine,
                    IntPtr.Zero, IntPtr.Zero, false,
                    NativeMethods.CREATE_NO_WINDOW,
                    IntPtr.Zero, null,
                    ref si, out NativeMethods.PROCESS_INFORMATION pi))
            {
                int err = Marshal.GetLastWin32Error();
                Log($"CreateProcessAsUser (bootstrap) failed: {err}");
                return 2;
            }

            NativeMethods.CloseHandle(pi.hProcess);
            NativeMethods.CloseHandle(pi.hThread);
            Log("Bootstrap process launched.");
        }
        finally
        {
            NativeMethods.CloseHandle(hPrimaryToken);
        }
    }
    finally
    {
        NativeMethods.CloseHandle(hToken);
    }

    // Step 3 — Poll for the session to appear in WTS session table
    Log("Waiting for session to appear...");
    int sessionId = -1;
    var deadline = DateTime.UtcNow.AddSeconds(30);

    while (DateTime.UtcNow < deadline)
    {
        sessionId = FindSessionForUser(username);
        if (sessionId >= 0)
        {
            Log($"Session found: ID={sessionId}");
            break;
        }
        Thread.Sleep(1000);
    }

    if (sessionId < 0)
    {
        Log($"Timed out waiting for session to appear for user {username}");
        return 5;
    }

    // Step 4 — Connect the session to make it Active
    // WTSConnectSession attaches the session to the local console (session 1)
    // giving it a real interactive desktop.
    Log($"Connecting session {sessionId} to make it Active...");

    if (!NativeMethods.WTSConnectSession(sessionId, 0, password, true))
    {
        int err = Marshal.GetLastWin32Error();
        // Error 5 (Access Denied) can happen if session is already Active — treat as success
        if (err != 5)
        {
            Log($"WTSConnectSession failed: {err}");
            return 5;
        }
        Log("WTSConnectSession returned Access Denied — session may already be Active, continuing.");
    }

    // Step 5 — Verify session is now Active
    Log("Verifying session is Active...");
    deadline = DateTime.UtcNow.AddSeconds(15);
    bool active = false;

    while (DateTime.UtcNow < deadline)
    {
        var state = GetSessionState(sessionId);
        if (state == NativeMethods.WTS_CONNECTSTATE_CLASS.WTSActive)
        {
            active = true;
            break;
        }
        Log($"Session state: {state}, waiting...");
        Thread.Sleep(1000);
    }

    if (!active)
    {
        Log($"Session {sessionId} did not become Active in time");
        return 5;
    }

    Log($"Session {sessionId} is Active for user {username}");
    Console.WriteLine(sessionId); // stdout — captured by session_manager.py
    return 0;
}

// ── Mode 2: InjectProcess ─────────────────────────────────────────────────────
// Injects a process into an existing active session for the user.
// Uses WTSQueryUserToken to get the session token, then CreateProcessAsUser.

static int InjectProcess(string username, string exePath, string? exeArgs)
{
    // Find the active session for this user
    int sessionId = FindSessionForUser(username);
    if (sessionId < 0)
    {
        Log($"No active session found for user {username}. Run --create-session first.");
        return 6;
    }

    Log($"Found session ID={sessionId} for user {username}");

    // Get the session token
    if (!NativeMethods.WTSQueryUserToken((uint)sessionId, out IntPtr hToken))
    {
        Log($"WTSQueryUserToken failed: {Marshal.GetLastWin32Error()}");
        return 2;
    }

    try
    {
        // Duplicate to primary token for CreateProcessAsUser
        if (!NativeMethods.DuplicateTokenEx(hToken,
                NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                NativeMethods.TOKEN_TYPE.TokenPrimary,
                out IntPtr hPrimaryToken))
        {
            Log($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");
            return 2;
        }

        try
        {
            var si = new NativeMethods.STARTUPINFO
            {
                cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>(),
                lpDesktop = "winsta0\\default"
            };

            string commandLine = string.IsNullOrEmpty(exeArgs)
                ? $"\"{exePath}\""
                : $"\"{exePath}\" {exeArgs}";

            Log($"Injecting into session {sessionId}: {commandLine}");

            if (!NativeMethods.CreateProcessAsUser(
                    hPrimaryToken, null, commandLine,
                    IntPtr.Zero, IntPtr.Zero, false,
                    NativeMethods.CREATE_NO_WINDOW,
                    IntPtr.Zero, null,
                    ref si, out NativeMethods.PROCESS_INFORMATION pi))
            {
                Log($"CreateProcessAsUser failed: {Marshal.GetLastWin32Error()}");
                return 3;
            }

            NativeMethods.CloseHandle(pi.hProcess);
            NativeMethods.CloseHandle(pi.hThread);
            Log($"Process launched successfully in session {sessionId} for user {username}");
            return 0;
        }
        finally
        {
            NativeMethods.CloseHandle(hPrimaryToken);
        }
    }
    finally
    {
        NativeMethods.CloseHandle(hToken);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static int FindSessionForUser(string username)
{
    IntPtr pSessions = IntPtr.Zero;
    uint count = 0;

    if (!NativeMethods.WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, ref pSessions, ref count))
        return -1;

    try
    {
        int structSize = Marshal.SizeOf<NativeMethods.WTS_SESSION_INFO>();
        for (int i = 0; i < count; i++)
        {
            var info = Marshal.PtrToStructure<NativeMethods.WTS_SESSION_INFO>(
                IntPtr.Add(pSessions, i * structSize));

            // Skip session 0 (services) and session 65536 (RDP listener)
            if (info.SessionId == 0 || info.SessionId == 65536)
                continue;

            // Query the username for this session
            string? sessionUser = GetSessionUsername((int)info.SessionId);

            if (sessionUser != null &&
                string.Equals(sessionUser, username, StringComparison.OrdinalIgnoreCase))
            {
                return (int)info.SessionId;
            }
        }
    }
    finally
    {
        NativeMethods.WTSFreeMemory(pSessions);
    }

    return -1;
}

static string? GetSessionUsername(int sessionId)
{
    if (!NativeMethods.WTSQuerySessionInformationW(
            IntPtr.Zero, (uint)sessionId,
            NativeMethods.WTS_INFO_CLASS.WTSUserName,
            out IntPtr pBuffer, out uint _))
        return null;

    try
    {
        return Marshal.PtrToStringUni(pBuffer);
    }
    finally
    {
        NativeMethods.WTSFreeMemory(pBuffer);
    }
}

static NativeMethods.WTS_CONNECTSTATE_CLASS GetSessionState(int sessionId)
{
    if (!NativeMethods.WTSQuerySessionInformationW(
            IntPtr.Zero, (uint)sessionId,
            NativeMethods.WTS_INFO_CLASS.WTSConnectState,
            out IntPtr pBuffer, out uint _))
        return NativeMethods.WTS_CONNECTSTATE_CLASS.WTSDown;

    try
    {
        return (NativeMethods.WTS_CONNECTSTATE_CLASS)Marshal.ReadInt32(pBuffer);
    }
    finally
    {
        NativeMethods.WTSFreeMemory(pBuffer);
    }
}

// ── CredentialStore ───────────────────────────────────────────────────────────

static class CredentialStore
{
    private static readonly string RootDir =
        Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))
        ?? AppContext.BaseDirectory;

    public static readonly string EncFile =
        Path.Combine(RootDir, "credentials.enc");

    public static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("AgentCredentials:SessionLauncher:v1");

    public record Credential(string Password, string Domain);

    public record UserEntry(
        string userid,
        string password,
        string? domain,
        string? name,
        string? email
    );

    public static Credential GetPassword(string username)
    {
        if (!File.Exists(EncFile))
            throw new FileNotFoundException(
                $"credentials.enc not found at {EncFile}. Run CredTool.exe --encrypt first.");

        byte[] encrypted = File.ReadAllBytes(EncFile);
        byte[] plain     = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
        string yaml      = Encoding.UTF8.GetString(plain);

        var users = ParseCredentialYaml(yaml);
        var user  = users.FirstOrDefault(u =>
            string.Equals(u.userid, username, StringComparison.OrdinalIgnoreCase));

        if (user == null)
            throw new KeyNotFoundException(
                $"No credentials found for '{username}' in credentials.enc.");

        return new Credential(user.password, user.domain ?? ".");
    }

    public static List<UserEntry> ParseCredentialYaml(string yaml)
    {
        var users  = new List<UserEntry>();
        var lines  = yaml.Split('\n');
        string? userid = null, password = null, domain = null, name = null, email = null;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if      (line.StartsWith("- userid:"))    { FlushUser(); userid    = Val(line); }
            else if (line.StartsWith("userid:"))      { FlushUser(); userid    = Val(line); }
            else if (line.StartsWith("password:"))    password = Val(line);
            else if (line.StartsWith("domain:"))      domain   = Val(line);
            else if (line.StartsWith("name:"))        name     = Val(line);
            else if (line.StartsWith("email:"))       email    = Val(line);
        }
        FlushUser();
        return users;

        void FlushUser()
        {
            if (userid != null && password != null)
                users.Add(new UserEntry(userid, password, domain, name, email));
            userid = password = domain = name = email = null;
        }

        static string Val(string line) => line.Substring(line.IndexOf(':') + 1).Trim().Trim('"');
    }
}

// ── P/Invoke ──────────────────────────────────────────────────────────────────

static class NativeMethods
{
    // Token constants
    public const uint TOKEN_ALL_ACCESS       = 0xF01FF;
    public const uint CREATE_NO_WINDOW       = 0x08000000;

    // Logon types
    public const uint LOGON32_LOGON_INTERACTIVE = 2;
    public const uint LOGON32_PROVIDER_DEFAULT  = 0;

    public enum SECURITY_IMPERSONATION_LEVEL { SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation }
    public enum TOKEN_TYPE { TokenPrimary = 1, TokenImpersonation }
    public enum WTS_CONNECTSTATE_CLASS { WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit }
    public enum WTS_INFO_CLASS { WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory, WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName, WTSConnectState, WTSClientBuildNumber, WTSClientName }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTS_SESSION_INFO
    {
        public uint SessionId;
        public string pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    // advapi32
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUserW(string lpszUsername, string lpszDomain, string lpszPassword,
        uint dwLogonType, uint dwLogonProvider, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(IntPtr hToken,
        string? lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    // wtsapi32
    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSEnumerateSessionsW(IntPtr hServer, uint Reserved, uint Version,
        ref IntPtr ppSessionInfo, ref uint pCount);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool WTSQuerySessionInformationW(IntPtr hServer, uint SessionId,
        WTS_INFO_CLASS WTSInfoClass, out IntPtr ppBuffer, out uint pBytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool WTSConnectSession(int LogonId, int TargetLogonId,
        string pPassword, bool bWait);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    // kernel32
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}