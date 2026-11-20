using System;
using System.Runtime.InteropServices;
using System.Windows.Interop;

namespace Win2FA.Core;

/// <summary>Sistem genelinde kısayol tuşu (varsayılan Ctrl+Alt+2).</summary>
public sealed class HotKey : IDisposable
{
    [DllImport("user32.dll")] static extern bool RegisterHotKey(IntPtr hWnd, int id, uint mods, uint vk);
    [DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    public const uint MOD_ALT = 1, MOD_CONTROL = 2, MOD_SHIFT = 4, MOD_NOREPEAT = 0x4000;
    const int WM_HOTKEY = 0x0312, Id = 0x2FA;
    readonly HwndSource _source;
    public event Action? Pressed;
    public bool Registered { get; }

    public HotKey(uint mods, uint vk)
    {
        _source = new HwndSource(new HwndSourceParameters("Win2FA.HotKey") { Width = 0, Height = 0, WindowStyle = 0 });
        _source.AddHook(WndProc);
        Registered = RegisterHotKey(_source.Handle, Id, mods | MOD_NOREPEAT, vk);
    }

    IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam.ToInt32() == Id) { Pressed?.Invoke(); handled = true; }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        UnregisterHotKey(_source.Handle, Id);
        _source.Dispose();
    }
}
