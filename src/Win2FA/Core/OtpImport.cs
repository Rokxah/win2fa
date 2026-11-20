using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Win2FA.Core;

/// <summary>otpauth:// ve Google Authenticator otpauth-migration:// QR içeriklerini çözer.</summary>
public static class OtpImport
{
    public sealed record MigrationResult(List<Account> Accounts, int BatchIndex, int BatchSize, int BatchId);

    public static Account ParseOtpAuth(string uri)
    {
        var u = new Uri(uri);
        if (!u.Host.Equals("totp", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("Yalnızca TOTP (zamana dayalı) hesaplar destekleniyor.");
        var label = Uri.UnescapeDataString(u.AbsolutePath.TrimStart('/'));
        var q = ParseQuery(u.Query);
        string issuer = q.GetValueOrDefault("issuer", "");
        string name = label;
        var colon = label.IndexOf(':');
        if (colon >= 0)
        {
            if (issuer == "") issuer = label[..colon].Trim();
            name = label[(colon + 1)..].Trim();
        }
        var secret = Base32.Normalize(q.GetValueOrDefault("secret", ""));
        Base32.Decode(secret); // doğrula
        return new Account
        {
            Issuer = issuer,
            Name = name,
            Secret = secret,
            Algorithm = q.GetValueOrDefault("algorithm", "SHA1").ToUpperInvariant(),
            Digits = int.TryParse(q.GetValueOrDefault("digits", "6"), out var d) && d is >= 6 and <= 10 ? d : 6,
            Period = int.TryParse(q.GetValueOrDefault("period", "30"), out var p) && p is > 0 and <= 300 ? p : 30,
        };
    }

    static Dictionary<string, string> ParseQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            dict[Uri.UnescapeDataString(kv[0])] = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : "";
        }
        return dict;
    }

    public static MigrationResult ParseMigration(string uri)
    {
        var u = new Uri(uri);
        var data = ParseQuery(u.Query).GetValueOrDefault("data", "");
        if (data == "") throw new FormatException("Aktarma QR kodunda veri yok.");
        var bytes = Convert.FromBase64String(data.Replace(' ', '+'));
        var accounts = new List<Account>();
        int batchSize = 1, batchIndex = 0, batchId = 0;
        foreach (var (field, value, varint) in ReadFields(bytes))
        {
            switch (field)
            {
                case 1: var acc = ParseOtpParameters(value!); if (acc != null) accounts.Add(acc); break;
                case 3: batchSize = (int)varint; break;
                case 4: batchIndex = (int)varint; break;
                case 5: batchId = (int)varint; break;
            }
        }
        return new MigrationResult(accounts, batchIndex, Math.Max(1, batchSize), batchId);
    }

    static Account? ParseOtpParameters(byte[] b)
    {
        byte[] secret = Array.Empty<byte>();
        string name = "", issuer = "";
        long alg = 1, digits = 1, type = 2;
        foreach (var (field, value, varint) in ReadFields(b))
        {
            switch (field)
            {
                case 1: secret = value!; break;
                case 2: name = Encoding.UTF8.GetString(value!); break;
                case 3: issuer = Encoding.UTF8.GetString(value!); break;
                case 4: alg = varint; break;
                case 5: digits = varint; break;
                case 6: type = varint; break;
            }
        }
        if (type == 1 || secret.Length == 0) return null; // HOTP desteklenmiyor
        if (issuer == "" && name.Contains(':'))
        {
            var i = name.IndexOf(':');
            issuer = name[..i].Trim();
            name = name[(i + 1)..].Trim();
        }
        else if (issuer != "" && name.StartsWith(issuer + ":"))
            name = name[(issuer.Length + 1)..].Trim();
        return new Account
        {
            Issuer = issuer,
            Name = name,
            Secret = Base32.Encode(secret),
            Algorithm = alg switch { 2 => "SHA256", 3 => "SHA512", 4 => "MD5", _ => "SHA1" },
            Digits = digits == 2 ? 8 : 6,
        };
    }

    // Minimal protobuf okuyucu: (alan no, length-delimited değer, varint değer)
    static List<(int field, byte[]? value, long varint)> ReadFields(byte[] buf)
    {
        var list = new List<(int, byte[]?, long)>();
        int pos = 0;
        while (pos < buf.Length)
        {
            long key = ReadVarint(buf, ref pos);
            int field = (int)(key >> 3), wire = (int)(key & 7);
            switch (wire)
            {
                case 0: list.Add((field, null, ReadVarint(buf, ref pos))); break;
                case 2:
                    int len = (int)ReadVarint(buf, ref pos);
                    list.Add((field, buf.AsSpan(pos, len).ToArray(), 0));
                    pos += len; break;
                case 1: pos += 8; break;
                case 5: pos += 4; break;
                default: throw new InvalidDataException("Bozuk aktarma verisi.");
            }
        }
        return list;
    }

    static long ReadVarint(byte[] buf, ref int pos)
    {
        long result = 0; int shift = 0;
        while (true)
        {
            byte b = buf[pos++];
            result |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return result;
            shift += 7;
        }
    }

    public static bool IsOtpText(string text) =>
        text.TrimStart().StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase) ||
        text.TrimStart().StartsWith("otpauth-migration://", StringComparison.OrdinalIgnoreCase);

    /// <summary>Herhangi bir QR metnini hesap listesine çevirir.</summary>
    public static List<Account> FromText(string text, out MigrationResult? migration)
    {
        migration = null;
        text = text.Trim();
        if (text.StartsWith("otpauth-migration://", StringComparison.OrdinalIgnoreCase))
        {
            migration = ParseMigration(text);
            return migration.Accounts;
        }
        if (text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            return new List<Account> { ParseOtpAuth(text) };
        throw new FormatException("Bu QR bir 2FA kodu içermiyor.");
    }
}
