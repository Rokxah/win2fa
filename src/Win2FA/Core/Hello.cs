using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace Win2FA.Core;

/// <summary>
/// Windows Hello (parmak izi / yüz / PIN). Hello'nun TPM'de tuttuğu RSA anahtarıyla sabit bir metni imzalatır;
/// RSA-PKCS1 imzası her seferinde aynı çıktığı için bu imzadan kasa anahtarını açan anahtar türetilir.
/// </summary>
public static class Hello
{
    const string KeyName = "Win2FA.VaultKey";

    public static async Task<bool> IsAvailableAsync()
    {
        try { return await KeyCredentialManager.IsSupportedAsync(); }
        catch { return false; }
    }

    /// <summary>Yeni Hello anahtarı oluşturur ve metni imzalar. Kullanıcı iptal ederse null.</summary>
    public static async Task<byte[]?> CreateAndSignAsync(byte[] challenge)
    {
        using var focus = FocusHelper.Start();
        var created = await KeyCredentialManager.RequestCreateAsync(KeyName, KeyCredentialCreationOption.ReplaceExisting);
        if (created.Status != KeyCredentialStatus.Success) return null;
        return await SignAsync(created.Credential, challenge);
    }

    /// <summary>Var olan Hello anahtarıyla imzalar. Kullanıcı iptal ederse ya da anahtar yoksa null.</summary>
    public static async Task<byte[]?> SignAsync(byte[] challenge)
    {
        using var focus = FocusHelper.Start();
        var opened = await KeyCredentialManager.OpenAsync(KeyName);
        if (opened.Status != KeyCredentialStatus.Success) return null;
        return await SignAsync(opened.Credential, challenge);
    }

    static async Task<byte[]?> SignAsync(KeyCredential cred, byte[] challenge)
    {
        var result = await cred.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge));
        if (result.Status != KeyCredentialStatus.Success) return null;
        return result.Result.ToArray();
    }

    public static async Task DeleteAsync()
    {
        try { await KeyCredentialManager.DeleteAsync(KeyName); } catch { }
    }

    /// <summary>
    /// Masaüstü uygulamalarında Hello penceresi bazen arkada açılıyor; birkaç saniye boyunca onu öne getirir.
    /// </summary>
    sealed class FocusHelper : IDisposable
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr FindWindow(string? cls, string? title);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hWnd);

        readonly CancellationTokenSource _cts = new();

        public static FocusHelper Start()
        {
            var h = new FocusHelper();
            var ct = h._cts.Token;
            Task.Run(async () =>
            {
                for (int i = 0; i < 40 && !ct.IsCancellationRequested; i++)
                {
                    var w = FindWindow("Credential Dialog Xaml Host", null);
                    if (w != IntPtr.Zero) { SetForegroundWindow(w); break; }
                    await Task.Delay(100);
                }
            });
            return h;
        }

        public void Dispose() => _cts.Cancel();
    }
}
