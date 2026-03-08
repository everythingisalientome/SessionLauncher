using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// ── Logging ───────────────────────────────────────────────────────────────────

const string LogFile = @"C:\agents\SessionLauncher.log";

static void Log(string message)
{
    try { File.AppendAllText(LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}"); } catch { }
    Console.WriteLine(message);
}

// ── Entry point ───────────────────────────────────────────────────────────────
// Normal usage:  SessionLauncher.exe --user agent_user_1 --exe "C:\..." --args "--port 8001"

string? targetUser = null;
string? exePath    = null;
string? exeArgs    = null;

for (int i = 0; i < args.Length; i++)
{
    if      (args[i] == "--user" && i + 1 < args.Length) targetUser = args[++i];
    else if (args[i] == "--exe"  && i + 1 < args.Length) exePath    = args[++i];
    else if (args[i] == "--args" && i + 1 < args.Length) exeArgs    = args[++i];
}

Log($"SessionLauncher called — user:{targetUser} exe:{exePath} args:{exeArgs}");

if (targetUser == null || exePath == null)
{
    Log("Error: Missing --user or --exe");
    Console.Error.WriteLine("Usage: SessionLauncher.exe --user <username> --exe <path> [--args <args>]");
    return 1;
}

// ── Load credentials from encrypted credentials.enc ───────────────────────────

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

// ── Launch process (auto-creates logon session for user) ──────────────────────

string commandLine = string.IsNullOrEmpty(exeArgs)
    ? $"\"{exePath}\""
    : $"\"{exePath}\" {exeArgs}";

Log($"Launching: {commandLine}");

bool success = LaunchWithLogon(targetUser, domain, password, exePath, commandLine);
if (!success)
{
    Log($"Error: LaunchWithLogon failed for user {targetUser}");
    return 3;
}

Log($"Process launched successfully for user: {targetUser}");
return 0;

// ── LaunchWithLogon ───────────────────────────────────────────────────────────
// Uses CreateProcessWithLogonW — auto-creates a new Windows logon session
// for the user without requiring a pre-existing RDP session.

static bool LaunchWithLogon(string username, string domain, string password,
                             string exePath, string commandLine)
{
    var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = "winsta0\\default" };

    bool ok = NativeMethods.CreateProcessWithLogonW(
        username, domain, password,
        NativeMethods.LOGON_NETCREDENTIALS_ONLY, // avoids profile load failure for non-interactive users
        exePath, commandLine,
        NativeMethods.CREATE_NO_WINDOW,
        IntPtr.Zero, null,
        ref si, out PROCESS_INFORMATION pi);

    if (!ok)
    {
        Console.Error.WriteLine($"CreateProcessWithLogonW failed: {Marshal.GetLastWin32Error()}");
        return false;
    }

    NativeMethods.CloseHandle(pi.hProcess);
    NativeMethods.CloseHandle(pi.hThread);
    return true;
}

// ── CredentialStore ───────────────────────────────────────────────────────────
// Reads credentials from credentials.enc (encrypted by CredTool.exe).
// credentials.enc lives next to SessionLauncher.exe.

static class CredentialStore
{
    // credentials.enc lives one folder above the exe:
    //   Server: C:\agents\SessionLauncher\credentials.enc
    //           C:\agents\SessionLauncher\launcher\SessionLauncher.exe
    //   Dev:    <sln folder>\credentials.enc
    //           <sln folder>\launcher\<exe>
    private static readonly string RootDir =
        Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))
        ?? AppContext.BaseDirectory;

    public static readonly string EncFile =
        Path.Combine(RootDir, "credentials.enc");

    // Fixed entropy — allows CredTool and SessionLauncher to share the same encrypted file
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

    // Minimal YAML parser for the credentials block — no extra dependencies needed.
    // Handles the format produced by CredTool --decrypt.
    public static List<UserEntry> ParseCredentialYaml(string yaml)
    {
        var users  = new List<UserEntry>();
        var lines  = yaml.Split('\n');

        string? userid = null, password = null, domain = null, name = null, email = null;

        foreach (var raw in lines)
        {
            var line = raw.Trim();

            if (line.StartsWith("- userid:"))   { FlushUser(); userid   = Val(line); }
            else if (line.StartsWith("userid:")) { FlushUser(); userid   = Val(line); }
            else if (line.StartsWith("password:")) password = Val(line);
            else if (line.StartsWith("domain:"))   domain   = Val(line);
            else if (line.StartsWith("name:"))     name     = Val(line);
            else if (line.StartsWith("email:"))    email    = Val(line);
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
    public const uint LOGON_WITH_PROFILE       = 0x00000001; // Load full user profile
    public const uint LOGON_NETCREDENTIALS_ONLY = 0x00000002; // Use caller environment (no profile load)
    public const uint CREATE_NO_WINDOW         = 0x08000000;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithLogonW(
        string lpUsername, string lpDomain, string lpPassword,
        uint dwLogonFlags,
        string? lpApplicationName, string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
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