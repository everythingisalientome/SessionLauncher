using System.Runtime.InteropServices;

// ── Logging ──────────────────────────────────────────────────────────────────

const string LogFile = @"C:\agents\SessionLauncher.log";

static void Log(string message)
{
    try { File.AppendAllText(LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}"); } catch { }
    Console.WriteLine(message);
}

// ── Entry point ──────────────────────────────────────────────────────────────
// Usage: SessionLauncher.exe --user agent_user_1 --exe "C:\agents\desktop_agent\desktop_agent.exe" --args "--port 8001"

const uint CREATE_NO_WINDOW = 0x08000000;

string? targetUser = null;
string? exePath = null;
string? exeArgs = null;

for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--user" && i + 1 < args.Length) targetUser = args[++i];
    else if (args[i] == "--exe" && i + 1 < args.Length) exePath = args[++i];
    else if (args[i] == "--args" && i + 1 < args.Length) exeArgs = args[++i];
}

Log($"SessionLauncher called — user:{targetUser} exe:{exePath} args:{exeArgs}");

if (targetUser == null || exePath == null)
{
    Log("Error: Missing --user or --exe");
    Console.Error.WriteLine("Usage: SessionLauncher.exe --user <username> --exe <path> [--args <args>]");
    return 1;
}

int sessionId = FindSessionForUser(targetUser);
if (sessionId < 0)
{
    Log($"Error: No active session found for user: {targetUser}");
    return 2;
}

Log($"Found session ID: {sessionId} for user: {targetUser}");

bool success = LaunchProcessInSession(sessionId, exePath, exeArgs ?? "", CREATE_NO_WINDOW);
if (!success)
{
    Log($"Error: Failed to launch process in session {sessionId}");
    return 3;
}

Log($"Process launched successfully in session {sessionId}");
return 0;

// ── Functions ────────────────────────────────────────────────────────────────

static int FindSessionForUser(string username)
{
    IntPtr ppSessionInfo = IntPtr.Zero;
    int count = 0;

    if (!NativeMethods.WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref count))
    {
        Console.Error.WriteLine($"WTSEnumerateSessions failed: {Marshal.GetLastWin32Error()}");
        return -1;
    }

    try
    {
        int dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
        IntPtr current = ppSessionInfo;

        for (int i = 0; i < count; i++)
        {
            var sessionInfo = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
            current = IntPtr.Add(current, dataSize);

            if (sessionInfo.State != WTS_CONNECTSTATE_CLASS.WTSActive)
                continue;

            if (NativeMethods.WTSQuerySessionInformation(IntPtr.Zero, sessionInfo.SessionID,
                WTS_INFO_CLASS.WTSUserName, out IntPtr namePtr, out int _))
            {
                string? sessionUser = Marshal.PtrToStringUni(namePtr);
                NativeMethods.WTSFreeMemory(namePtr);

                if (string.Equals(sessionUser, username, StringComparison.OrdinalIgnoreCase))
                    return sessionInfo.SessionID;
            }
        }
    }
    finally
    {
        NativeMethods.WTSFreeMemory(ppSessionInfo);
    }

    return -1;
}

static bool LaunchProcessInSession(int sessionId, string exePath, string exeArgs, uint createFlags)
{
    IntPtr userToken = IntPtr.Zero;

    if (!NativeMethods.WTSQueryUserToken((uint)sessionId, ref userToken))
    {
        Console.Error.WriteLine($"WTSQueryUserToken failed: {Marshal.GetLastWin32Error()}");
        return false;
    }

    try
    {
        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.lpDesktop = "winsta0\\default";

        string commandLine = string.IsNullOrEmpty(exeArgs)
            ? $"\"{exePath}\""
            : $"\"{exePath}\" {exeArgs}";

        Console.WriteLine($"Launching: {commandLine}");

        bool result = NativeMethods.CreateProcessAsUser(
            userToken, null, commandLine,
            IntPtr.Zero, IntPtr.Zero, false,
            createFlags, IntPtr.Zero, null,
            ref si, out PROCESS_INFORMATION pi);

        if (!result)
        {
            Console.Error.WriteLine($"CreateProcessAsUser failed: {Marshal.GetLastWin32Error()}");
            return false;
        }

        NativeMethods.CloseHandle(pi.hProcess);
        NativeMethods.CloseHandle(pi.hThread);
        return true;
    }
    finally
    {
        NativeMethods.CloseHandle(userToken);
    }
}

// ── Types ────────────────────────────────────────────────────────────────────

static class NativeMethods
{
    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSEnumerateSessions(
        IntPtr hServer, int reserved, int version,
        ref IntPtr ppSessionInfo, ref int pCount);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQuerySessionInformation(
        IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass,
        out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQueryUserToken(uint sessionId, ref IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken, string? lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

[StructLayout(LayoutKind.Sequential)]
struct WTS_SESSION_INFO
{
    public int SessionID;
    [MarshalAs(UnmanagedType.LPStr)]
    public string pWinStationName;
    public WTS_CONNECTSTATE_CLASS State;
}

enum WTS_CONNECTSTATE_CLASS
{
    WTSActive, WTSConnected, WTSConnectQuery, WTSShadow,
    WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit
}

enum WTS_INFO_CLASS
{
    WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory,
    WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName,
    WTSDomainName, WTSConnectState, WTSClientBuildNumber,
    WTSClientName, WTSClientDirectory, WTSClientProductId,
    WTSClientHardwareId, WTSClientAddress, WTSClientDisplay,
    WTSClientProtocolType
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
struct STARTUPINFO
{
    public int cb;
    public string? lpReserved, lpDesktop, lpTitle;
    public int dwX, dwY, dwXSize, dwYSize;
    public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    public short wShowWindow, cbReserved2;
    public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
}

[StructLayout(LayoutKind.Sequential)]
struct PROCESS_INFORMATION
{
    public IntPtr hProcess, hThread;
    public int dwProcessId, dwThreadId;
}