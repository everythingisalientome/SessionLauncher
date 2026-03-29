using System.Security.Cryptography;
using System.Text;

namespace SessionService;

// ── CredentialStore ───────────────────────────────────────────────────────────
// Reads credentials from credentials.enc encrypted by CredTool.exe.
// credentials.enc lives one folder above the exe:
//   C:\agents\SessionLauncher\credentials.enc
//   C:\agents\SessionService\SessionService.exe  ← exe is here
//   → looks one level up: C:\agents\SessionLauncher\credentials.enc
//
// ── CyberArk placeholder ──────────────────────────────────────────────────────
// TODO: Replace GetPassword() body with CyberArk SDK call:
//
//   var cyberArk = new CyberArkClient(vaultAddress, appId, safe, objectName);
//   var creds = await cyberArk.GetCredentialAsync(username);
//   return new Credential(creds.Password, creds.Domain);
//
// ─────────────────────────────────────────────────────────────────────────────

public static class CredentialStore
{
    private static readonly string RootDir =
        Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))
        ?? AppContext.BaseDirectory;

    public static readonly string EncFile =
        Path.Combine(RootDir, "SessionLauncher", "credentials.enc");

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
        byte[] plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
        string yaml = Encoding.UTF8.GetString(plain);

        var users = ParseCredentialYaml(yaml);
        var user = users.FirstOrDefault(u =>
            string.Equals(u.userid, username, StringComparison.OrdinalIgnoreCase));

        if (user == null)
            throw new KeyNotFoundException(
                $"No credentials found for '{username}' in credentials.enc.");

        return new Credential(user.password, user.domain ?? ".");
    }

    public static List<UserEntry> GetAllUsers()
    {
        if (!File.Exists(EncFile))
            throw new FileNotFoundException(
                $"credentials.enc not found at {EncFile}. Run CredTool.exe --encrypt first.");

        byte[] encrypted = File.ReadAllBytes(EncFile);
        byte[] plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.LocalMachine);
        string yaml = Encoding.UTF8.GetString(plain);

        return ParseCredentialYaml(yaml);
    }

    public static List<UserEntry> ParseCredentialYaml(string yaml)
    {
        var users = new List<UserEntry>();
        var lines = yaml.Split('\n');
        string? userid = null, password = null, domain = null, name = null, email = null;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.StartsWith("- userid:")) { FlushUser(); userid = Val(line); }
            else if (line.StartsWith("userid:")) { FlushUser(); userid = Val(line); }
            else if (line.StartsWith("password:")) password = Val(line);
            else if (line.StartsWith("domain:")) domain = Val(line);
            else if (line.StartsWith("name:")) name = Val(line);
            else if (line.StartsWith("email:")) email = Val(line);
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