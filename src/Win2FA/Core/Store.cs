using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Win2FA.Core;

/// <summary>
/// Hesap deposu. Katmanlar:
///  1) Kasa anahtarı = PBKDF2-SHA256(ana şifre, 600.000 tur). Hesaplar bununla AES-256-GCM ile şifreli.
///  2) İsteğe bağlı Windows Hello: kasa anahtarının bir kopyası, Hello'nun TPM'deki anahtarıyla
///     imzalanan sabit bir metinden türetilen anahtarla şifreli saklanır. Hello doğrulaması olmadan açılmaz.
///  3) Hepsinin üstünde Windows DPAPI (oturum açan kullanıcıya bağlı).
/// </summary>
public sealed class Store
{
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Win2FA.v1");
    const int Iterations = 600_000;
    public static string? DirOverride { get; set; }  // testler için
    public static string Dir => DirOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Win2FA");
    public static string FilePath => Path.Combine(Dir, "accounts.dat");

    sealed class Envelope
    {
        public int V { get; set; } = 2;
        public string Salt { get; set; } = "";
        public int Iter { get; set; }
        public string Nonce { get; set; } = "";
        public string Data { get; set; } = "";
        public string Tag { get; set; } = "";
        // Windows Hello
        public string? HelloChallenge { get; set; }
        public string? HelloWrapped { get; set; }   // nonce(12) | tag(16) | şifreli kasa anahtarı(32)
        public bool HelloOffered { get; set; }
    }

    Envelope? _env;            // diskteki şifreli kayıt
    List<Account>? _legacy;    // v1 (şifresiz) kayıt, ana şifre belirlenince taşınır
    byte[]? _key;
    byte[]? _salt;
    readonly object _gate = new();

    public List<Account> Accounts { get; private set; } = new();
    public event Action? Changed;
    public event Action? LockChanged;

    /// <summary>Olayları arayüz iş parçacığında çalıştırmak için (App ayarlar).</summary>
    public Action<Action>? Invoker { get; set; }
    void Raise(Action? ev) { if (ev == null) return; if (Invoker != null) Invoker(ev); else ev(); }

    public bool HasPassword => _env != null;
    public bool IsUnlocked => _key != null;
    public bool HelloEnabled => _env?.HelloWrapped != null;
    public bool HelloOffered => _env?.HelloOffered ?? false;
    public byte[]? HelloChallenge => _env?.HelloChallenge == null ? null : Convert.FromBase64String(_env.HelloChallenge);

    /// <summary>Dosyayı okur ama şifreli kısmı çözmez.</summary>
    public void Load()
    {
        if (!File.Exists(FilePath)) return;
        var plain = ProtectedData.Unprotect(File.ReadAllBytes(FilePath), Entropy, DataProtectionScope.CurrentUser);
        try
        {
            if (plain.Length > 0 && plain[0] == (byte)'[')
                _legacy = JsonSerializer.Deserialize<List<Account>>(plain) ?? new();
            else
                _env = JsonSerializer.Deserialize<Envelope>(plain);
        }
        finally { Array.Clear(plain); }
    }

    static byte[] Derive(string password, byte[] salt, int iter) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iter, HashAlgorithmName.SHA256, 32);

    /// <summary>İlk kurulum: ana şifreyi belirler, varsa eski kayıtları taşır.</summary>
    public void SetupPassword(string password)
    {
        lock (_gate)
        {
            if (HasPassword) throw new InvalidOperationException("Ana şifre zaten belirlenmiş.");
            _salt = RandomNumberGenerator.GetBytes(16);
            _key = Derive(password, _salt, Iterations);
            Accounts = _legacy ?? new();
            _legacy = null;
            SaveCore();
        }
        Raise(LockChanged);
    }

    /// <summary>Şifre doğruysa true döner ve hesapları çözer.</summary>
    public bool Unlock(string password)
    {
        if (_env == null) return false;
        var salt = Convert.FromBase64String(_env.Salt);
        var key = Derive(password, salt, _env.Iter);
        return UnlockWithKey(key);
    }

    bool UnlockWithKey(byte[] key)
    {
        lock (_gate)
        {
            if (_env == null) return false;
            var ct = Convert.FromBase64String(_env.Data);
            var plain = new byte[ct.Length];
            try
            {
                using var gcm = new AesGcm(key, 16);
                gcm.Decrypt(Convert.FromBase64String(_env.Nonce), ct, Convert.FromBase64String(_env.Tag), plain);
            }
            catch (CryptographicException)
            {
                Array.Clear(key);
                return false;
            }
            Accounts = JsonSerializer.Deserialize<List<Account>>(plain) ?? new();
            Array.Clear(plain);
            _key = key;
            _salt = Convert.FromBase64String(_env.Salt);
        }
        Raise(LockChanged);
        return true;
    }

    public void Lock()
    {
        lock (_gate)
        {
            if (_key == null) return;
            Array.Clear(_key);
            _key = null;
            foreach (var a in Accounts) a.Secret = "";
            Accounts = new();
        }
        Raise(LockChanged);
    }

    public bool ChangePassword(string oldPassword, string newPassword)
    {
        lock (_gate)
        {
            if (!IsUnlocked) return false;
            var check = Derive(oldPassword, _salt!, _env!.Iter);
            bool ok = CryptographicOperations.FixedTimeEquals(check, _key);
            Array.Clear(check);
            if (!ok) return false;
            _salt = RandomNumberGenerator.GetBytes(16);
            Array.Clear(_key!);
            _key = Derive(newPassword, _salt, Iterations);
            // Kasa anahtarı değişti: Hello kopyası artık geçersiz, kapat.
            _env.HelloWrapped = null;
            _env.HelloChallenge = null;
            SaveCore();
        }
        Raise(Changed);
        return true;
    }

    // ---------- Windows Hello ----------

    /// <summary>Hello için rastgele bir metin üretir (imzalanacak).</summary>
    public static byte[] NewHelloChallenge() => RandomNumberGenerator.GetBytes(32);

    static byte[] WrapKeyFromSignature(byte[] signature) => SHA256.HashData(signature);

    /// <summary>Kilit açıkken çağrılır: kasa anahtarını Hello imzasından türeyen anahtarla saklar.</summary>
    public void EnableHello(byte[] challenge, byte[] signature)
    {
        lock (_gate)
        {
            if (_key == null) throw new InvalidOperationException("Kasa kilitli.");
            var wrapKey = WrapKeyFromSignature(signature);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var ct = new byte[_key.Length];
            using (var gcm = new AesGcm(wrapKey, 16)) gcm.Encrypt(nonce, _key, ct, tag);
            Array.Clear(wrapKey);
            _env!.HelloChallenge = Convert.ToBase64String(challenge);
            _env.HelloWrapped = Convert.ToBase64String(nonce.Concat(tag).Concat(ct).ToArray());
            _env.HelloOffered = true;
            SaveCore();
        }
    }

    public void DisableHello()
    {
        lock (_gate)
        {
            if (_env == null) return;
            _env.HelloWrapped = null;
            _env.HelloChallenge = null;
            _env.HelloOffered = true;
            if (_key != null) SaveCore(); else WriteEnvelope();
        }
    }

    public void MarkHelloOffered()
    {
        lock (_gate)
        {
            if (_env == null || _env.HelloOffered) return;
            _env.HelloOffered = true;
            WriteEnvelope();
        }
    }

    /// <summary>Hello imzasıyla kilidi açar.</summary>
    public bool UnlockWithHello(byte[] signature)
    {
        if (_env?.HelloWrapped == null) return false;
        var blob = Convert.FromBase64String(_env.HelloWrapped);
        var wrapKey = WrapKeyFromSignature(signature);
        var key = new byte[blob.Length - 28];
        try
        {
            using var gcm = new AesGcm(wrapKey, 16);
            gcm.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), key);
        }
        catch (CryptographicException) { return false; }
        finally { Array.Clear(wrapKey); }
        return UnlockWithKey(key);
    }

    // ---------- Kaydetme ----------

    public void Save()
    {
        lock (_gate) SaveCore();
        Raise(Changed);
    }

    void SaveCore()
    {
        if (_key == null) throw new InvalidOperationException("Kasa kilitli.");
        var plain = JsonSerializer.SerializeToUtf8Bytes(Accounts);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(_key, 16)) gcm.Encrypt(nonce, plain, ct, tag);
        Array.Clear(plain);
        var old = _env;
        _env = new Envelope
        {
            Salt = Convert.ToBase64String(_salt!),
            Iter = Iterations,
            Nonce = Convert.ToBase64String(nonce),
            Data = Convert.ToBase64String(ct),
            Tag = Convert.ToBase64String(tag),
            HelloChallenge = old?.HelloChallenge,
            HelloWrapped = old?.HelloWrapped,
            HelloOffered = old?.HelloOffered ?? false,
        };
        WriteEnvelope();
    }

    void WriteEnvelope()
    {
        Directory.CreateDirectory(Dir);
        var envBytes = JsonSerializer.SerializeToUtf8Bytes(_env);
        var tmp = FilePath + ".tmp";
        File.WriteAllBytes(tmp, ProtectedData.Protect(envBytes, Entropy, DataProtectionScope.CurrentUser));
        File.Move(tmp, FilePath, true);
    }

    /// <summary>Aynı gizli anahtar zaten varsa eklemez. Eklenen sayıyı döner.</summary>
    public int AddRange(IEnumerable<Account> items)
    {
        int added = 0;
        lock (_gate)
        {
            foreach (var a in items)
            {
                if (Accounts.Any(x => x.Secret == a.Secret)) continue;
                Accounts.Add(a);
                added++;
            }
        }
        if (added > 0) Save();
        return added;
    }

    public void Remove(Account a) { lock (_gate) Accounts.Remove(a); Save(); }

    public void MarkUsed(Account a) { a.UseCount++; a.LastUsed = DateTime.Now; Save(); }
}
