using System;
using System.Text;

namespace Win2FA.Core;

public static class Base32
{
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static byte[] Decode(string input)
    {
        var s = input.Trim().Replace(" ", "").Replace("-", "").TrimEnd('=').ToUpperInvariant();
        if (s.Length == 0) throw new FormatException("Gizli anahtar boş.");
        var output = new byte[s.Length * 5 / 8];
        int buffer = 0, bits = 0, index = 0;
        foreach (var c in s)
        {
            int v = Alphabet.IndexOf(c);
            if (v < 0) throw new FormatException("Geçersiz Base32 karakteri: " + c);
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output[index++] = (byte)(buffer >> bits);
            }
        }
        return output;
    }

    public static string Encode(byte[] data)
    {
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(Alphabet[(buffer >> bits) & 31]);
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static string Normalize(string input) =>
        input.Trim().Replace(" ", "").Replace("-", "").TrimEnd('=').ToUpperInvariant();
}
