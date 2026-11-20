using System;
using Microsoft.Win32;

namespace Win2FA.Core;

public static class AutoStart
{
    const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string Name = "Win2FA";

    public static bool IsEnabled
    {
        get
        {
            using var k = Registry.CurrentUser.OpenSubKey(Key);
            return k?.GetValue(Name) != null;
        }
    }

    public static void Set(bool on)
    {
        using var k = Registry.CurrentUser.CreateSubKey(Key);
        if (on) k.SetValue(Name, "\"" + Environment.ProcessPath + "\"");
        else k.DeleteValue(Name, false);
    }
}
