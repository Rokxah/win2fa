using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Win2FA.Core;

/// <summary>Kodu panoya koyar; pano geçmişine/bulut eşitlemeye düşmemesini ister ve süre dolunca siler.</summary>
public static class SecureClipboard
{
    static DispatcherTimer? _timer;
    static string? _last;

    public static void Copy(string text, int clearAfterSeconds = 30)
    {
        var data = new DataObject();
        data.SetText(text);
        data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[] { 0 }));
        data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
        data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
        for (int i = 0; i < 10; i++)
        {
            try { Clipboard.SetDataObject(data, true); break; }
            catch (System.Runtime.InteropServices.COMException) { System.Threading.Thread.Sleep(50); }
        }
        _last = text;
        _timer?.Stop();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(clearAfterSeconds) };
        _timer.Tick += (_, _) =>
        {
            _timer!.Stop();
            try { if (Clipboard.ContainsText() && Clipboard.GetText() == _last) Clipboard.Clear(); } catch { }
        };
        _timer.Start();
    }
}
