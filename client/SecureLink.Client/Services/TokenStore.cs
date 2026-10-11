using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace SecureLink.Client.Services;

public record StoredToken(string Token, DateTime ExpiresAtUtc);

/// <summary>
/// Keeps the sign-in token in Windows Credential Manager (the same vault Windows
/// uses for saved network passwords) so the user stays signed in between launches.
/// The vault encrypts each entry with the Windows account's own key, so the token
/// is never written anywhere in plain text and other Windows users can't read it.
/// </summary>
public class TokenStore
{
    public const string DefaultTarget = "SecureLink:AuthToken";

    private readonly string _target;

    /// <param name="target">Name of the vault entry. Only tests pass a different
    /// one, so a test run can't overwrite the real user's saved sign-in.</param>
    public TokenStore(string target = DefaultTarget)
    {
        _target = target;
    }

    public void Save(StoredToken token)
    {
        var blob = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(token));
        var blobPtr = Marshal.AllocHGlobal(blob.Length);
        try
        {
            Marshal.Copy(blob, 0, blobPtr, blob.Length);
            var credential = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = _target,
                UserName = "SecureLink",
                CredentialBlob = blobPtr,
                CredentialBlobSize = (uint)blob.Length,
                // Stays on this PC for this Windows account; never roams.
                Persist = CRED_PERSIST_LOCAL_MACHINE,
            };
            if (!CredWrite(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            Marshal.FreeHGlobal(blobPtr);
        }
    }

    /// <summary>Returns the saved token, or null if there isn't one (or it's unreadable).</summary>
    public StoredToken? Load()
    {
        if (!CredRead(_target, CRED_TYPE_GENERIC, 0, out var credentialPtr))
            return null;
        try
        {
            var credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPtr);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
                return null;
            var blob = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, blob, 0, blob.Length);
            return JsonSerializer.Deserialize<StoredToken>(Encoding.UTF8.GetString(blob));
        }
        catch (JsonException)
        {
            return null;
        }
        finally
        {
            CredFree(credentialPtr);
        }
    }

    /// <summary>Removes the saved token. Safe to call when nothing is saved.</summary>
    public void Clear()
    {
        CredDelete(_target, CRED_TYPE_GENERIC, 0);
    }

    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_LOCAL_MACHINE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
}
