using System.Security.Cryptography;
using System.Text;

// ── CredTool.exe ──────────────────────────────────────────────────────────────
// Manages the encrypted credentials file used by SessionLauncher.exe.
//
// Commands:
//   CredTool.exe --encrypt   Encrypts credentials.yaml → credentials.enc
//                            Then DELETES credentials.yaml from disk.
//
//   CredTool.exe --decrypt   Decrypts credentials.enc → credentials.yaml
//                            For editing. Prompts to re-encrypt when done.
//
//   CredTool.exe --verify    Verifies credentials.enc is readable.
//                            Shows usernames only — never shows passwords.
//
// IMPORTANT:
//   - Must be run on the same machine as SessionLauncher.exe (DPAPI machine-scope).
//   - Copying credentials.enc to another machine will NOT work.
//   - credentials.yaml must never be left on disk unencrypted.
// ─────────────────────────────────────────────────────────────────────────────

// Paths are relative to CredTool.exe location
// credentials files live one folder above the exe:
//   Server: C:\agents\SessionLauncher\credentials.enc
//           C:\agents\SessionLauncher\credtool\CredTool.exe
//   Dev:    <sln folder>\credentials.enc
//           <sln folder>\credtool\CredTool.exe
string rootDir  = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))
                  ?? AppContext.BaseDirectory;
string yamlFile = Path.Combine(rootDir, "credentials.yaml");
string encFile  = Path.Combine(rootDir, "credentials.enc");

// Fixed entropy — must match SessionLauncher exactly
byte[] entropy  = Encoding.UTF8.GetBytes("AgentCredentials:SessionLauncher:v1");

if (args.Length != 1)
{
    PrintUsage();
    return 1;
}

switch (args[0])
{
    case "--encrypt": return RunEncrypt();
    case "--decrypt": return RunDecrypt();
    case "--verify":  return RunVerify();
    default:
        Console.Error.WriteLine($"Unknown command: {args[0]}");
        PrintUsage();
        return 1;
}

// ── --encrypt ─────────────────────────────────────────────────────────────────

int RunEncrypt()
{
    if (!File.Exists(yamlFile))
    {
        Console.Error.WriteLine($"Error: credentials.yaml not found at:\n  {yamlFile}");
        Console.Error.WriteLine("Create the file first, then run --encrypt.");
        return 1;
    }

    Console.WriteLine($"Encrypting: {yamlFile}");

    try
    {
        byte[] plain     = File.ReadAllBytes(yamlFile);
        byte[] encrypted = ProtectedData.Protect(plain, entropy, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(encFile, encrypted);
        Console.WriteLine($"Encrypted:  {encFile}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Encryption failed: {ex.Message}");
        return 2;
    }

    // Securely delete the plaintext YAML
    try
    {
        // Overwrite with zeros before deleting so it can't be recovered
        long size = new FileInfo(yamlFile).Length;
        File.WriteAllBytes(yamlFile, new byte[size]);
        File.Delete(yamlFile);
        Console.WriteLine($"Deleted:    credentials.yaml (securely wiped)");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Warning: Could not delete credentials.yaml: {ex.Message}");
        Console.Error.WriteLine("Please delete it manually.");
        return 3;
    }

    Console.WriteLine("\nDone. credentials.enc is ready for use by SessionLauncher.exe.");
    return 0;
}

// ── --decrypt ─────────────────────────────────────────────────────────────────

int RunDecrypt()
{
    if (!File.Exists(encFile))
    {
        Console.Error.WriteLine($"Error: credentials.enc not found at:\n  {encFile}");
        return 1;
    }

    if (File.Exists(yamlFile))
    {
        Console.Write("credentials.yaml already exists. Overwrite? (y/n): ");
        if (Console.ReadLine()?.Trim().ToLower() != "y")
        {
            Console.WriteLine("Aborted.");
            return 0;
        }
    }

    Console.WriteLine($"Decrypting: {encFile}");

    try
    {
        byte[] encrypted = File.ReadAllBytes(encFile);
        byte[] plain     = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(yamlFile, plain);
        Console.WriteLine($"Decrypted:  {yamlFile}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Decryption failed: {ex.Message}");
        Console.Error.WriteLine("This machine may not match the machine that created credentials.enc.");
        return 2;
    }

    Console.WriteLine("\ncredentials.yaml is ready for editing.");
    Console.WriteLine("When done, run:  CredTool.exe --encrypt");
    Console.WriteLine("This will re-encrypt and delete the plaintext file.");
    return 0;
}

// ── --verify ──────────────────────────────────────────────────────────────────

int RunVerify()
{
    if (!File.Exists(encFile))
    {
        Console.Error.WriteLine($"Error: credentials.enc not found at:\n  {encFile}");
        return 1;
    }

    Console.WriteLine($"Verifying: {encFile}");

    try
    {
        byte[] encrypted = File.ReadAllBytes(encFile);
        byte[] plain     = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.LocalMachine);
        string yaml      = Encoding.UTF8.GetString(plain);

        // Parse and show usernames only — never show passwords
        var users = new List<string>();
        foreach (var line in yaml.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("- userid:") || trimmed.StartsWith("userid:"))
            {
                string uid = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim().Trim('"');
                users.Add(uid);
            }
        }

        Console.WriteLine($"\ncredentials.enc is valid. Found {users.Count} user(s):");
        foreach (var u in users)
            Console.WriteLine($"  - {u}");

        Console.WriteLine($"\nFile size: {new FileInfo(encFile).Length} bytes");
        Console.WriteLine($"Modified:  {File.GetLastWriteTime(encFile):yyyy-MM-dd HH:mm:ss}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Verification failed: {ex.Message}");
        return 2;
    }

    return 0;
}

// ── Usage ─────────────────────────────────────────────────────────────────────

static void PrintUsage()
{
    Console.WriteLine("CredTool.exe — Credential file manager for SessionLauncher");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  --encrypt   Encrypt credentials.yaml → credentials.enc (deletes yaml)");
    Console.WriteLine("  --decrypt   Decrypt credentials.enc  → credentials.yaml (for editing)");
    Console.WriteLine("  --verify    Verify credentials.enc is readable (shows usernames only)");
    Console.WriteLine();
    Console.WriteLine("Workflow:");
    Console.WriteLine("  1. Edit credentials.yaml");
    Console.WriteLine("  2. CredTool.exe --encrypt");
    Console.WriteLine("  3. To update: CredTool.exe --decrypt, edit, CredTool.exe --encrypt");
}