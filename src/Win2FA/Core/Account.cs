using System;

namespace Win2FA.Core;

public sealed class Account
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Issuer { get; set; } = "";
    public string Name { get; set; } = "";
    public string Secret { get; set; } = "";      // Base32
    public string Algorithm { get; set; } = "SHA1";
    public int Digits { get; set; } = 6;
    public int Period { get; set; } = 30;
    public int UseCount { get; set; }
    public DateTime? LastUsed { get; set; }

    public string Title => string.IsNullOrWhiteSpace(Issuer) ? Name : Issuer;
    public string Subtitle => string.IsNullOrWhiteSpace(Issuer) ? "" : Name;
}
