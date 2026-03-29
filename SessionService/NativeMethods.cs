using System.Runtime.InteropServices;

namespace SessionService;

// ── P/Invoke declarations ─────────────────────────────────────────────────────

internal static class NativeMethods
{
    // ── Constants ─────────────────────────────────────────────────────────────

    public const uint TOKEN_ALL_ACCESS = 0xF01FF;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint LOGON32_LOGON_INTERACTIVE = 2;
    public const uint LOGON32_PROVIDER_DEFAULT = 0;
    public const uint LOGON_WITH_PROFILE = 0x00000001;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;

    public const string SE_TCB_NAME = "SeTcbPrivilege";
    public const string SE_ASSIGNPRIMARYTOKEN = "SeAssignPrimaryTokenPrivilege";
    public const string SE_INCREASE_QUOTA = "SeIncreaseQuotaPrivilege";

    // ── Enums ─────────────────────────────────────────────────────────────────

    public enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation
    }

    public enum TOKEN_TYPE { TokenPrimary = 1, TokenImpersonation }

    public enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive, WTSConnected, WTSConnectQuery, WTSShadow,
        WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit
    }

    public enum WTS_INFO_CLASS
    {
        WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory,
        WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName,
        WTSDomainName, WTSConnectState, WTSClientBuildNumber, WTSClientName
    }

    // ── Structs ───────────────────────────────────────────────────────────────

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

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    // ── advapi32 ──────────────────────────────────────────────────────────────

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUserW(string lpszUsername, string lpszDomain,
        string lpszPassword, uint dwLogonType, uint dwLogonProvider, out IntPtr phToken);

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

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(
        string lpUsername, string lpDomain, string lpPassword,
        uint dwLogonFlags,
        string? lpApplicationName, string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle,
        uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValueW(string? lpSystemName,
        string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState,
        uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    // ── wtsapi32 ──────────────────────────────────────────────────────────────

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSEnumerateSessionsW(IntPtr hServer,
        uint Reserved, uint Version,
        ref IntPtr ppSessionInfo, ref uint pCount);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool WTSQuerySessionInformationW(IntPtr hServer,
        uint SessionId, WTS_INFO_CLASS WTSInfoClass,
        out IntPtr ppBuffer, out uint pBytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSLogoffSession(IntPtr hServer, int SessionId, bool bWait);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    // ── kernel32 ──────────────────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}