using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;

namespace SessionService;

// ── ProcessInjector ───────────────────────────────────────────────────────────
// Creates isolated RDSH sessions via loopback RDP and injects processes.
// Requires LocalSystem with SE_TCB_NAME — satisfied by Windows Service.
//
// Session creation strategy:
//   - Each session gets a unique loopback IP: 127.0.0.2, 127.0.0.3, ...
//     This eliminates credential collision in SYSTEM's credential store.
//   - /add (not /generic) for cmdkey — uses NLA/CredSSP for silent auth.
//     NLA authenticates before the graphical session loads, bypassing LogonUI.
//     When enablecredsspsupport:i:0 was used, LogonUI loaded instead and
//     mstsc aborted trying to render it from Session 0 (reason code 12).
//   - alternate shell:s:cmd.exe /k — replaces explorer.exe as the session
//     shell. When mstsc disconnects after establishing the session, cmd.exe
//     keeps running and the session stays alive as Disconnected (not logged off).
//   - mstsc.exe PID captured directly from RunProcess — no race condition.

public static class ProcessInjector
{
    private static readonly ILogger Log =
        LoggerFactory.Create(b => b.AddEventLog()).CreateLogger("ProcessInjector");

    // ── EnablePrivilege ───────────────────────────────────────────────────────

    public static void EnablePrivilege(string privilege)
    {
        if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY,
                out IntPtr hToken))
            throw new InvalidOperationException(
                $"OpenProcessToken failed: {Marshal.GetLastWin32Error()}");

        try
        {
            if (!NativeMethods.LookupPrivilegeValueW(null, privilege, out var luid))
                throw new InvalidOperationException(
                    $"LookupPrivilegeValue({privilege}) failed: {Marshal.GetLastWin32Error()}");

            var tp = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new[]
                {
                    new NativeMethods.LUID_AND_ATTRIBUTES
                    {
                        Luid       = luid,
                        Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
                    }
                }
            };

            NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp,
                (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);

            int err = Marshal.GetLastWin32Error();
            if (err != 0)
                throw new InvalidOperationException(
                    $"AdjustTokenPrivileges({privilege}) failed: {err}");
        }
        finally
        {
            NativeMethods.CloseHandle(hToken);
        }
    }

    // ── CreateRdpSession ──────────────────────────────────────────────────────
    // Creates an isolated RDSH session via loopback RDP.
    //
    // Steps:
    //   1. Store credentials with /add (NLA path) — auth happens at network
    //      layer, LogonUI never loads, no rendering required from Session 0.
    //   2. Write .rdp file with alternate shell cmd.exe /k — session stays
    //      alive as Disconnected after mstsc drops, because cmd.exe is still
    //      running inside it. Without this, session logs off (reason code 12).
    //   3. Launch mstsc — PID captured directly, no race condition.
    //   4. Poll for session. Accept both Active and Disconnected states.
    //
    // Returns (windowsSessionId, holderPid, loopbackIp, rdpFilePath).

    public static (int sessionId, int holderPid, string loopbackIp, string rdpFilePath)
        CreateRdpSession(string username, string domain, string password,
            int sessionIndex, int timeoutSeconds = 60)
    {
        string loopbackIp = $"127.0.0.{sessionIndex + 1}";
        string rdpFile    = Path.Combine(@"C:\Windows\Temp", $"session_{username}.rdp");
        string domainUser = domain == "." ? $".\\{username}" : $"{domain}\\{username}";

        try
        {
            // Step 1 — store credentials using /add (NLA/CredSSP path).
            // NLA authenticates silently at the network layer before any GUI loads.
            // This avoids the LogonUI rendering trap that caused reason code 12.
            RunProcess("cmdkey.exe",
                $"/add:TERMSRV/{loopbackIp} /user:{domainUser} /pass:{password}",
                waitForExit: true);

            // Step 2 — write .rdp file.
            // NLA is implicitly enabled (no enablecredsspsupport override).
            // authentication level:i:2 forces silent connection despite localhost cert warnings.
            File.WriteAllText(rdpFile,
                $"full address:s:{loopbackIp}\r\n" +
                $"username:s:{domainUser}\r\n" +
                $"authentication level:i:2\r\n" +
                $"prompt for credentials:i:0\r\n" +
                $"negotiate security layer:i:1\r\n" +
                $"desktopwidth:i:1024\r\n" +
                $"desktopheight:i:768\r\n" +
                $"session bpp:i:16\r\n" +
                $"audiomode:i:2\r\n" +
                $"redirectprinters:i:0\r\n" +
                $"redirectclipboard:i:0\r\n" +
                $"bitmapcachepersistenable:i:0\r\n" +
                $"disable wallpaper:i:1\r\n" +
                $"disable themes:i:1\r\n");

            // Step 3 — launch mstsc minimized. 
            // CreateNoWindow=true causes mstsc to exit immediately (reason code 12)
            // because it has no window handle to maintain the RDP display pipeline.
            // Running minimized gives it a real window handle while staying out of the way.
            int mstscPid = RunMstsc($"\"{rdpFile}\"");

            // Step 4 — poll for session. Accept Active or Disconnected —
            // mstsc may drop before our next poll, leaving session as Disconnected.
            var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
            while (DateTime.UtcNow < deadline)
            {
                int sessionId = FindSessionForUser(username);
                if (sessionId >= 0)
                    return (sessionId, mstscPid, loopbackIp, rdpFile);

                Thread.Sleep(2000);
            }

            throw new TimeoutException(
                $"RDP session for {username} via {loopbackIp} did not appear within {timeoutSeconds}s");
        }
        catch
        {
            CleanupLoopback(loopbackIp, rdpFile);
            throw;
        }
    }

    // ── CleanupLoopback ───────────────────────────────────────────────────────

    public static void CleanupLoopback(string loopbackIp, string rdpFilePath)
    {
        try { File.Delete(rdpFilePath); } catch { }
        try { RunProcess("cmdkey.exe", $"/delete:TERMSRV/{loopbackIp}",
                waitForExit: true); } catch { }
    }

    // ── RunProcess ────────────────────────────────────────────────────────────
    // Used for cmdkey and other background utilities — no window, no shell.

    private static int RunProcess(string exe, string args, bool waitForExit)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName        = exe,
            Arguments       = args,
            CreateNoWindow  = true,
            UseShellExecute = false,
        };

        var proc = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start: {exe} {args}");

        if (waitForExit)
            proc.WaitForExit(10_000);

        return proc.Id;
    }

    // ── RunMstsc ──────────────────────────────────────────────────────────────
    // Launches mstsc minimized via UseShellExecute=true.
    // WindowStyle only takes effect when UseShellExecute=true.
    // A real (minimized) window handle is required for mstsc to maintain the
    // RDP display pipeline — CreateNoWindow causes immediate exit (reason code 12).

    private static int RunMstsc(string args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName        = @"C:\Windows\System32\mstsc.exe",
            Arguments       = args,
            UseShellExecute = true,
            WindowStyle     = System.Diagnostics.ProcessWindowStyle.Minimized,
        };

        var proc = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start mstsc.exe");

        return proc.Id;
    }

    // ── InjectProcess ─────────────────────────────────────────────────────────

    public static int InjectProcess(int windowsSessionId, string exePath, string? exeArgs)
    {
        EnablePrivilege(NativeMethods.SE_TCB_NAME);

        if (!NativeMethods.WTSQueryUserToken((uint)windowsSessionId, out IntPtr hToken))
            throw new InvalidOperationException(
                $"WTSQueryUserToken(session={windowsSessionId}) failed: {Marshal.GetLastWin32Error()}");

        try
        {
            if (!NativeMethods.DuplicateTokenEx(hToken,
                    NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    NativeMethods.TOKEN_TYPE.TokenPrimary,
                    out IntPtr hPrimaryToken))
                throw new InvalidOperationException(
                    $"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");

            try
            {
                var si = new NativeMethods.STARTUPINFO
                {
                    cb        = Marshal.SizeOf<NativeMethods.STARTUPINFO>(),
                    lpDesktop = "winsta0\\default"
                };

                string commandLine = string.IsNullOrEmpty(exeArgs)
                    ? $"\"{exePath}\""
                    : $"\"{exePath}\" {exeArgs}";

                if (!NativeMethods.CreateProcessAsUser(
                        hPrimaryToken, null, commandLine,
                        IntPtr.Zero, IntPtr.Zero, false,
                        NativeMethods.CREATE_NO_WINDOW,
                        IntPtr.Zero, null,
                        ref si, out NativeMethods.PROCESS_INFORMATION pi))
                    throw new InvalidOperationException(
                        $"CreateProcessAsUser failed: {Marshal.GetLastWin32Error()}");

                int pid = pi.dwProcessId;
                NativeMethods.CloseHandle(pi.hProcess);
                NativeMethods.CloseHandle(pi.hThread);
                return pid;
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

    // ── FindSessionForUser ────────────────────────────────────────────────────

    public static int FindSessionForUser(string username)
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

                if (info.SessionId == 0 || info.SessionId == 65536) continue;

                if (info.State != NativeMethods.WTS_CONNECTSTATE_CLASS.WTSActive &&
                    info.State != NativeMethods.WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                    continue;

                string? sessionUser = GetSessionUsername((int)info.SessionId);
                if (sessionUser != null &&
                    string.Equals(sessionUser, username, StringComparison.OrdinalIgnoreCase))
                    return (int)info.SessionId;
            }
        }
        finally
        {
            NativeMethods.WTSFreeMemory(pSessions);
        }

        return -1;
    }

    // ── GetSessionUsername ────────────────────────────────────────────────────

    public static string? GetSessionUsername(int sessionId)
    {
        if (!NativeMethods.WTSQuerySessionInformationW(
                IntPtr.Zero, (uint)sessionId,
                NativeMethods.WTS_INFO_CLASS.WTSUserName,
                out IntPtr pBuffer, out uint _))
            return null;

        try { return Marshal.PtrToStringUni(pBuffer); }
        finally { NativeMethods.WTSFreeMemory(pBuffer); }
    }
}