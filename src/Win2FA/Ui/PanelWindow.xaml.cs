using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Win2FA.Core;

namespace Win2FA.Ui;

public sealed class AccountRow : INotifyPropertyChanged
{
    static readonly Brush Normal = Frozen(0xF2, 0xF2, 0xF5);
    static readonly Brush Urgent = Frozen(0xFF, 0x6B, 0x5B);
    static readonly Brush[] Palette =
    {
        Frozen(0x4C, 0x8D, 0xFF), Frozen(0x9B, 0x6B, 0xFF), Frozen(0xE8, 0x5D, 0x9E), Frozen(0xF0, 0x8A, 0x3C),
        Frozen(0x2F, 0xB5, 0x8A), Frozen(0x1F, 0xA8, 0xC9), Frozen(0xD9, 0x4F, 0x4F), Frozen(0x6C, 0x7A, 0x89),
    };
    const double RingUnits = 22; // halka çevresi (çizgi kalınlığı biriminde)

    static Brush Frozen(byte r, byte g, byte b) { var x = new SolidColorBrush(Color.FromRgb(r, g, b)); x.Freeze(); return x; }

    public Account Account { get; }
    public string Title => Account.Title;
    public string Subtitle => Account.Subtitle;
    public string Initial { get; }
    public Brush AvatarBrush { get; }
    public string Code { get; private set; } = "";
    public string CodeDisplay => Code.Length == 6 ? Code[..3] + " " + Code[3..] : Code.Length == 8 ? Code[..4] + " " + Code[4..] : Code;
    public int Seconds { get; private set; }
    public string SecondsText => Seconds + " sn";
    public Brush CodeBrush => Seconds <= 5 ? Urgent : Normal;
    public DoubleCollection RingDash { get; private set; } = new();
    public string CopyIcon { get; private set; } = "";
    public string SearchKey { get; }

    public AccountRow(Account a)
    {
        Account = a;
        SearchKey = PanelWindow.Fold(a.Issuer + " " + a.Name);
        var t = Account.Title.Trim();
        Initial = t.Length > 0 ? t[..1].ToUpper(new CultureInfo("tr-TR")) : "?";
        int h = 0;
        foreach (var c in PanelWindow.Fold(Account.Title)) h = h * 31 + c;
        AvatarBrush = Palette[Math.Abs(h % Palette.Length)];
        Refresh();
    }

    public void Refresh()
    {
        try { Code = Totp.Generate(Account); } catch { Code = "hata"; }
        Seconds = Totp.SecondsLeft(Account);
        var dash = new DoubleCollection { RingUnits * Seconds / Account.Period, 100 };
        dash.Freeze();
        RingDash = dash;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
    }

    public void MarkCopied()
    {
        CopyIcon = "";
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CopyIcon)));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

public partial class PanelWindow : Window
{
    List<AccountRow> _rows = new();
    readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    bool _suppressDeactivate, _busy, _helloTriedThisOpen;
    bool? _helloAvailable;

    public PanelWindow()
    {
        InitializeComponent();
        _timer.Tick += (_, _) => { foreach (var r in _rows) r.Refresh(); };
        // İlk kurulumda (şifre belirlenirken) odak kaybında kapanmasın.
        Deactivated += (_, _) => { if (!_suppressDeactivate && App.Store.HasPassword) HideNow(); };
        App.Store.Changed += () => { if (IsVisible && App.Store.IsUnlocked) Rebuild(); };
        App.Store.LockChanged += () => { if (IsVisible) ShowState(); };
    }

    public void Toggle()
    {
        if (IsVisible) { HideNow(); return; }
        App.Touch();
        _helloTriedThisOpen = false;
        PositionNearTray();
        Show();
        Activate();
        ShowState();
    }

    Action? _afterUnlock;

    /// <summary>Kilit ekranını gösterir; kilit açılınca paneli kapatıp verilen işi sürdürür.</summary>
    public void RequestUnlock(Action then)
    {
        _afterUnlock = then;
        if (!IsVisible) Toggle(); else { Activate(); ShowState(); }
    }

    void ShowState()
    {
        var store = App.Store;
        bool unlocked = store.IsUnlocked;
        VaultView.Visibility = unlocked ? Visibility.Visible : Visibility.Collapsed;
        LockView.Visibility = unlocked ? Visibility.Collapsed : Visibility.Visible;
        Pw1.Clear(); Pw2.Clear();
        LockError.Visibility = Visibility.Collapsed;

        if (unlocked && _afterUnlock != null)
        {
            // Kilit bir işlem için açıldı (hesap ekle, ekran QR'ı): paneli kasayı kilitlemeden kapat, işe devam et.
            var then = _afterUnlock;
            _afterUnlock = null;
            HideNow(keepUnlocked: true);
            Dispatcher.BeginInvoke(then);
            return;
        }

        if (unlocked)
        {
            Search.Text = "";
            Toast.Text = "";
            Rebuild();
            _timer.Start();
            Search.Focus();
            Keyboard.Focus(Search);
            _ = UpdateHelloToggleAsync();
        }
        else
        {
            _timer.Stop();
            _rows = new();
            List.ItemsSource = null;
            bool setup = !store.HasPassword;
            LockTitle.Text = setup ? "Ana şifre belirle" : "Win2FA kilitli";
            LockHint.Text = setup
                ? "Kodlar bu şifreyle şifrelenecek ve her açılışta sorulacak. En az 8 karakter olsun."
                : "Kodları görmek için ana şifreni gir.";
            Pw2.Visibility = setup ? Visibility.Visible : Visibility.Collapsed;
            SetupWarn.Visibility = setup ? Visibility.Visible : Visibility.Collapsed;
            UnlockButton.Content = setup ? "Şifreyi kaydet" : "Kilidi aç";
            HelloButton.Visibility = !setup && store.HelloEnabled ? Visibility.Visible : Visibility.Collapsed;
            Pw1.Focus();
            Keyboard.Focus(Pw1);
            if (!setup && store.HelloEnabled && !_helloTriedThisOpen)
            {
                _helloTriedThisOpen = true;
                Dispatcher.BeginInvoke(new Action(() => HelloUnlock_Click(this, new RoutedEventArgs())), DispatcherPriority.ApplicationIdle);
            }
        }
    }

    async Task<bool> HelloAvailableAsync() => _helloAvailable ??= await Hello.IsAvailableAsync();

    async Task UpdateHelloToggleAsync()
    {
        bool avail = await HelloAvailableAsync();
        HelloToggle.Visibility = avail ? Visibility.Visible : Visibility.Collapsed;
        HelloToggle.Foreground = App.Store.HelloEnabled ? (Brush)FindResource("Accent") : (Brush)FindResource("Fg2");
        HelloToggle.ToolTip = App.Store.HelloEnabled ? "Windows Hello açık (kapatmak için tıkla)" : "Windows Hello ile açmayı etkinleştir";
    }

    async void HelloUnlock_Click(object sender, RoutedEventArgs e)
    {
        var challenge = App.Store.HelloChallenge;
        if (_busy || challenge == null || App.Store.IsUnlocked || !IsVisible) return;
        _busy = true;
        _suppressDeactivate = true;
        try
        {
            var sig = await Hello.SignAsync(challenge);
            if (sig == null) { Activate(); Pw1.Focus(); return; }   // iptal edildi: şifreyle devam
            bool ok = await Task.Run(() => App.Store.UnlockWithHello(sig));
            Array.Clear(sig);
            Activate();
            if (!ok) { LockError.Text = "Windows Hello doğrulaması kasayı açamadı. Ana şifreni gir."; LockError.Visibility = Visibility.Visible; }
            else { App.Touch(); ShowState(); }
        }
        catch (Exception ex) { LockError.Text = "Windows Hello: " + ex.Message; LockError.Visibility = Visibility.Visible; }
        finally { _busy = false; _suppressDeactivate = false; }
    }

    /// <summary>Şifreyle ilk açılıştan sonra bir kez Hello önerir.</summary>
    async Task OfferHelloAsync()
    {
        var store = App.Store;
        if (!IsVisible || store.HelloEnabled || store.HelloOffered || !await HelloAvailableAsync()) return;
        _suppressDeactivate = true;
        var answer = MessageBox.Show(this,
            "Bundan sonra kilidi Windows Hello (parmak izi, yüz tanıma ya da Windows PIN) ile de açmak ister misin?\n\n" +
            "Ana şifren yine geçerli olacak.", "Windows Hello", MessageBoxButton.YesNo, MessageBoxImage.Question);
        _suppressDeactivate = false;
        if (answer == MessageBoxResult.Yes) await EnableHelloAsync();
        else store.MarkHelloOffered();
        Activate();
    }

    async Task EnableHelloAsync()
    {
        _suppressDeactivate = true;
        try
        {
            var challenge = Store.NewHelloChallenge();
            var sig = await Hello.CreateAndSignAsync(challenge);
            if (sig == null) { App.Store.MarkHelloOffered(); return; }
            App.Store.EnableHello(challenge, sig);
            Array.Clear(sig);
            Toast.Text = "✓ Windows Hello etkin";
        }
        catch (Exception ex) { Toast.Text = "Windows Hello açılamadı: " + ex.Message; }
        finally { _suppressDeactivate = false; Activate(); await UpdateHelloToggleAsync(); }
    }

    async void HelloToggle_Click(object sender, RoutedEventArgs e)
    {
        if (!App.Store.HelloEnabled) { await EnableHelloAsync(); return; }
        _suppressDeactivate = true;
        var answer = MessageBox.Show(this, "Windows Hello ile kilit açma kapatılsın mı? Sonra yalnızca ana şifre çalışır.",
            "Windows Hello", MessageBoxButton.YesNo, MessageBoxImage.Question);
        _suppressDeactivate = false;
        if (answer == MessageBoxResult.Yes) { App.Store.DisableHello(); await Hello.DeleteAsync(); }
        Activate();
        await UpdateHelloToggleAsync();
    }

    void Pw_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (sender == Pw1 && Pw2.Visibility == Visibility.Visible && Pw2.Password.Length == 0) { Pw2.Focus(); return; }
            Unlock_Click(sender, e);
        }
        else if (e.Key == Key.Escape) HideNow();
    }

    async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var store = App.Store;
        var pw = Pw1.Password;
        void Error(string msg) { LockError.Text = msg; LockError.Visibility = Visibility.Visible; }

        if (!store.HasPassword)
        {
            if (pw.Length < 8) { Error("Şifre en az 8 karakter olmalı."); return; }
            if (pw != Pw2.Password) { Error("Şifreler aynı değil."); return; }
        }
        else if (pw.Length == 0) return;

        _busy = true;
        UnlockButton.IsEnabled = false;
        UnlockButton.Content = "Açılıyor…";
        try
        {
            bool ok = true;
            if (!store.HasPassword) await Task.Run(() => store.SetupPassword(pw));
            else ok = await Task.Run(() => store.Unlock(pw));
            if (!ok)
            {
                Pw1.Clear();
                Error("Şifre yanlış.");
                ShowStateButtonOnly();
                Pw1.Focus();
                return;
            }
            App.Touch();
            ShowState();
            _busy = false;
            await OfferHelloAsync();
        }
        catch (Exception ex) { Error(ex.Message); ShowStateButtonOnly(); }
        finally { _busy = false; UnlockButton.IsEnabled = true; }
    }

    void ShowStateButtonOnly() => UnlockButton.Content = App.Store.HasPassword ? "Kilidi aç" : "Şifreyi kaydet";

    /// <summary>Paneli kapatır. Her kapanışta kasa kilitlenir; bir sonraki açılışta yeniden doğrulama gerekir.</summary>
    void HideNow(bool keepUnlocked = false)
    {
        _timer.Stop();
        Pw1.Clear(); Pw2.Clear();
        // Hide() aynı anda Deactivated olayını tetikler; o da HideNow()'u varsayılan (kilitleyen) hâliyle
        // yeniden çağırıp keepUnlocked isteğini bozuyordu. Gizlerken bu olayı yok say.
        bool prev = _suppressDeactivate;
        _suppressDeactivate = true;
        try { Hide(); }
        finally { _suppressDeactivate = prev; }
        if (!keepUnlocked)
        {
            _afterUnlock = null;   // kullanıcı vazgeçti: bekleyen işi unut
            App.Store.Lock();
        }
    }

    void PositionNearTray()
    {
        var wa = SystemParameters.WorkArea;
        Left = wa.Right - Width - 2;
        Top = wa.Bottom - Height - 2;
    }

    void Rebuild()
    {
        _rows = App.Store.Accounts
            .OrderByDescending(a => a.UseCount >= 3)       // sık kullanılanlar üstte
            .ThenByDescending(a => a.UseCount >= 3 ? a.UseCount : 0)
            .ThenBy(a => a.Title, StringComparer.Create(new CultureInfo("tr-TR"), true))
            .ThenBy(a => a.Name, StringComparer.Create(new CultureInfo("tr-TR"), true))
            .Select(a => new AccountRow(a)).ToList();
        ApplyFilter();
    }

    void ApplyFilter()
    {
        var terms = Fold(Search.Text).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var shown = terms.Length == 0 ? _rows : _rows.Where(r => terms.All(t => r.SearchKey.Contains(t))).ToList();
        List.ItemsSource = shown;
        if (shown.Count > 0) List.SelectedIndex = 0;
        Placeholder.Visibility = Search.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        Empty.Visibility = shown.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Empty.Text = _rows.Count == 0
            ? "Henüz hesap yok.\nSağ üstteki + ile Google Authenticator'dan aktarabilirsin."
            : "Eşleşen hesap yok.";
    }

    /// <summary>Türkçe karakterleri sadeleştirir: "Gülşen İş" → "gulsen is".</summary>
    public static string Fold(string s)
    {
        var lower = s.ToLower(new CultureInfo("tr-TR"));
        var sb = new StringBuilder(lower.Length);
        foreach (var c in lower)
        {
            sb.Append(c switch
            {
                'ı' => 'i', 'ğ' => 'g', 'ü' => 'u', 'ş' => 's', 'ö' => 'o', 'ç' => 'c',
                'â' => 'a', 'î' => 'i', 'û' => 'u', _ => c,
            });
        }
        return sb.ToString();
    }

    void Search_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    void Search_Focus(object sender, KeyboardFocusChangedEventArgs e) =>
        SearchBorder.BorderBrush = Search.IsKeyboardFocused ? (Brush)FindResource("Accent") : new SolidColorBrush(Color.FromRgb(0x34, 0x34, 0x3C));

    void Search_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Down: Move(1); e.Handled = true; break;
            case Key.Up: Move(-1); e.Handled = true; break;
            case Key.Enter: CopyRow(List.SelectedItem as AccountRow); e.Handled = true; break;
            case Key.Escape: HideNow(); e.Handled = true; break;
            case Key.F2: Edit_Click(sender, e); e.Handled = true; break;
        }
    }

    void List_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { CopyRow(List.SelectedItem as AccountRow); e.Handled = true; }
        else if (e.Key == Key.Escape) { HideNow(); e.Handled = true; }
        else if (e.Key == Key.F2) { Edit_Click(sender, e); e.Handled = true; }
        else if (e.Key == Key.Delete) { Delete_Click(sender, e); e.Handled = true; }
    }

    void Move(int delta)
    {
        if (List.Items.Count == 0) return;
        List.SelectedIndex = Math.Clamp(List.SelectedIndex + delta, 0, List.Items.Count - 1);
        List.ScrollIntoView(List.SelectedItem);
    }

    async void CopyRow(AccountRow? row)
    {
        if (row == null) return;
        row.Refresh();
        SecureClipboard.Copy(row.Code);
        App.Store.MarkUsed(row.Account);
        App.Touch();
        row.MarkCopied();
        Toast.Text = "✓ " + row.Title + " kopyalandı";
        await Task.Delay(650);
        if (IsVisible) HideNow();
    }

    void RowCopy_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is AccountRow row)
        {
            List.SelectedItem = row;
            CopyRow(row);
        }
    }

    void List_MouseDoubleClick(object sender, MouseButtonEventArgs e) => CopyRow(List.SelectedItem as AccountRow);
    void Copy_Click(object sender, RoutedEventArgs e) => CopyRow(List.SelectedItem as AccountRow);

    void RowMore_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not AccountRow row) return;
        List.SelectedItem = row;
        RowMenu.PlacementTarget = (UIElement)sender;
        RowMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        RowMenu.IsOpen = true;
    }

    void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is not AccountRow row) return;
        _suppressDeactivate = true;
        try { new EditWindow(row.Account) { Owner = this }.ShowDialog(); }
        finally { _suppressDeactivate = false; }
        App.Touch();
        Activate();
        Search.Focus();
    }

    void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is not AccountRow row) return;
        _suppressDeactivate = true;
        var ok = MessageBox.Show(this,
            $"\"{row.Title}\" ({row.Subtitle}) silinsin mi?\n\nBu hesabın gizli anahtarı Win2FA'dan kalıcı olarak silinir. " +
            "Telefonunda kopyası yoksa bu servise giriş yapamayabilirsin.",
            "Hesabı sil", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        _suppressDeactivate = false;
        if (ok == MessageBoxResult.Yes) App.Store.Remove(row.Account);
        Activate();
    }

    void Lock_Click(object sender, RoutedEventArgs e) => App.Store.Lock();
    // İçe aktarma penceresi açıkken kasa açık kalır; pencere kapanınca kilitlenir.
    void Add_Click(object sender, RoutedEventArgs e) { HideNow(keepUnlocked: true); ImportWindow.ShowSingle(); }
    void Scan_Click(object sender, RoutedEventArgs e)
    {
        HideNow(keepUnlocked: true);
        ImportWindow.ScanScreenAndImport();
        if (!ImportWindow.IsOpen) App.Store.Lock();
    }
}
