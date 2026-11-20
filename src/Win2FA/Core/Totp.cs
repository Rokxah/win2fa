using System;
using System.Security.Cryptography;

namespace Win2FA.Core;

public static class Totp
{
    public static string Generate(Account a, DateTimeOffset? now = null)
    {
        var t = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / a.Period;
        var counter = BitConverter.GetBytes(t);
        if (BitConverter.IsLittleEndian) Array.Reverse(counter);
        var key = Base32.Decode(a.Secret);
        byte[] hash = a.Algorithm.ToUpperInvariant() switch
        {
            "SHA256" => HMACSHA256.HashData(key, counter),
            "SHA512" => HMACSHA512.HashData(key, counter),
            "MD5" => HMACMD5.HashData(key, counter),
            _ => HMACSHA1.HashData(key, counter),
        };
        int offset = hash[^1] & 0x0F;
        int bin = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        long mod = (long)Math.Pow(10, a.Digits);
        return (bin % mod).ToString().PadLeft(a.Digits, '0');
    }

    public static int SecondsLeft(Account a) =>
        a.Period - (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() % a.Period);
}
