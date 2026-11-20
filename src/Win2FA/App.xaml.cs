using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Threading;
using System.Windows;
using Win2FA.Core;
using Win2FA.Ui;
using Forms = System.Windows.Forms;

namespace Win2FA;

public partial class App : System.Windows.Application
{
    public static Store Store { get; } = new();
    Forms.NotifyIcon? _tray;
    HotKey? _hotKey;
    PanelWindow? _panel;
    Mutex? _single;
    static DateTime _lastActivity = DateTime.Now;
    public static readonly TimeSpan AutoLockAfter = TimeSpan.FromMinutes(5);
    System.Windows.Threading.DispatcherTimer? _lockTimer;

    public static void Touch() => _lastActivity = DateTime.Now;

    /// <summary>
    /// Kasa açıksa true döner. Kilitliyse paneli açıp şifre/Hello ister, false döner;
    /// kilit açılınca <paramref name="then"/> çalıştırılır (yarım kalan iş devam eder).
    /// </summary>
    public static bool EnsureUnlocked(Action then)
    {
        if (Store.IsUnlocked) return true;
        if (Current is App app) app._panel?.RequestUnlock(then);
        return false;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _single = new Mutex(true, "Win2FA.SingleInstance", out bool first);
        if (!first) { Shutdown(); return; }

        DispatcherUnhandledException += (_, ex) =>
        {
            System.Windows.MessageBox.Show(ex.Exception.Message, "Win2FA", MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;
        };

        Store.Invoker = a => { if (Dispatcher.CheckAccess()) a(); else Dispatcher.Invoke(a); };
        try { Store.Load(); }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show("Hesaplar okunamadı: " + ex.Message, "Win2FA", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(); return;
        }

        _panel = new PanelWindow();

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Aç  (Ctrl+Alt+2)", null, (_, _) => _panel.Toggle());
        menu.Items.Add("Hesap ekle / içe aktar…", null, (_, _) => ImportWindow.ShowSingle());
        menu.Items.Add("Ekrandaki QR kodu oku", null, (_, _) => ImportWindow.ScanScreenAndImport());
        menu.Items.Add("Şimdi kilitle", null, (_, _) => Store.Lock());
        menu.Items.Add(new Forms.ToolStripSeparator());
        var autostart = new Forms.ToolStripMenuItem("Windows açılışında başlat") { Checked = AutoStart.IsEnabled, CheckOnClick = true };
        autostart.CheckedChanged += (_, _) => AutoStart.Set(autostart.Checked);
        menu.Items.Add(autostart);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Çıkış", null, (_, _) => ExitApp());

        _tray = new Forms.NotifyIcon
        {
            Icon = MakeLockIcon(),
            Text = "Win2FA",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _tray.MouseClick += (_, ev) => { if (ev.Button == Forms.MouseButtons.Left) _panel.Toggle(); };

        // Ctrl+Alt+2
        _hotKey = new HotKey(HotKey.MOD_CONTROL | HotKey.MOD_ALT, 0x32);
        _hotKey.Pressed += () => _panel.Toggle();
        if (!_hotKey.Registered)
            _tray.ShowBalloonTip(4000, "Win2FA", "Ctrl+Alt+2 kısayolu başka bir uygulama tarafından kullanılıyor.", Forms.ToolTipIcon.Warning);

        // Otomatik kilit: 5 dk işlem yoksa ya da Windows oturumu kilitlenince
        _lockTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _lockTimer.Tick += (_, _) =>
        {
            if (Store.IsUnlocked && DateTime.Now - _lastActivity > AutoLockAfter && !_panel.IsActive) Store.Lock();
        };
        _lockTimer.Start();
        Microsoft.Win32.SystemEvents.SessionSwitch += (_, ev) =>
        {
            if (ev.Reason is Microsoft.Win32.SessionSwitchReason.SessionLock or Microsoft.Win32.SessionSwitchReason.ConsoleDisconnect
                or Microsoft.Win32.SessionSwitchReason.RemoteDisconnect)
                Dispatcher.Invoke(() => Store.Lock());
        };

        if (!Store.HasPassword)
        {
            _panel.Toggle();
        }
    }

    public static void Notify(string text)
    {
        if (Current is App app && app._tray != null)
            app._tray.ShowBalloonTip(2500, "Win2FA", text, Forms.ToolTipIcon.None);
    }

    void ExitApp()
    {
        _hotKey?.Dispose();
        if (_tray != null) { _tray.Visible = false; _tray.Dispose(); }
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _hotKey?.Dispose();
        _tray?.Dispose();
        base.OnExit(e);
    }

    /// <summary>Basit bir kilit simgesi çizer (ayrı .ico dosyasına gerek kalmasın).</summary>
    static Icon MakeLockIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using var shackle = new Pen(Color.FromArgb(235, 235, 240), 3.5f);
            g.DrawArc(shackle, 9, 3, 14, 16, 180, 180);
            g.DrawLine(shackle, 9, 11, 9, 15);
            g.DrawLine(shackle, 23, 11, 23, 15);
            using var body = new SolidBrush(Color.FromArgb(76, 141, 255));
            using var path = new GraphicsPath();
            path.AddArc(5, 14, 6, 6, 180, 90); path.AddArc(21, 14, 6, 6, 270, 90);
            path.AddArc(21, 25, 6, 6, 0, 90); path.AddArc(5, 25, 6, 6, 90, 90);
            path.CloseFigure();
            g.FillPath(body, path);
            using var f = new Font("Segoe UI", 7f, System.Drawing.FontStyle.Bold);
            g.DrawString("2FA", f, Brushes.White, 4.5f, 17.5f);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }
}
