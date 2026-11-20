using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using Win2FA.Core;

namespace Win2FA.Ui;

public partial class ImportWindow : Window
{
    static ImportWindow? _instance;

    // Google Authenticator çoklu QR takibi: batchId → okunan indeksler
    static readonly Dictionary<int, HashSet<int>> Batches = new();

    public ImportWindow()
    {
        InitializeComponent();
        Closed += (_, _) => { _instance = null; App.Store.LockChanged -= OnLock; App.Store.Lock(); };
        App.Store.LockChanged += OnLock;
    }

    public static bool IsOpen => _instance != null;

    public static void ShowSingle()
    {
        if (!App.EnsureUnlocked(ShowSingle)) return;
        _instance ??= new ImportWindow();
        _instance.Show();
        _instance.Activate();
    }

    public static void ScanScreenAndImport()
    {
        if (!App.EnsureUnlocked(ScanScreenAndImport)) return;
        try
        {
            System.Threading.Thread.Sleep(200); // panel ekrandan tamamen çekilsin
            var texts = QrReader.ScanScreens().Where(OtpImport.IsOtpText).ToList();
            var msg = texts.Count == 0
                ? "Ekranda 2FA QR kodu bulunamadı. QR kodun tamamen görünür olduğundan emin ol."
                : HandleTexts(texts);
            MessageBox.Show(msg, "Win2FA", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        finally
        {
            // İçe aktarma penceresi açık değilse kasa yeniden kilitlensin.
            if (!IsOpen) App.Store.Lock();
        }
    }

    /// <summary>QR metinlerini içe aktarır, kullanıcıya gösterilecek özeti döner.</summary>
    public static string HandleTexts(IEnumerable<string> texts)
    {
        if (!App.Store.IsUnlocked) return "Win2FA kilitlendi. Kilidi açıp tekrar dene.";
        App.Touch();
        int found = 0, added = 0;
        var errors = new List<string>();
        string progress = "";
        foreach (var t in texts)
        {
            try
            {
                var accs = OtpImport.FromText(t, out var mig);
                found += accs.Count;
                added += App.Store.AddRange(accs);
                if (mig != null && mig.BatchSize > 1)
                {
                    if (!Batches.TryGetValue(mig.BatchId, out var set)) Batches[mig.BatchId] = set = new HashSet<int>();
                    set.Add(mig.BatchIndex);
                    progress = set.Count >= mig.BatchSize
                        ? $"Tüm QR kodları okundu ({mig.BatchSize}/{mig.BatchSize})."
                        : $"{set.Count}/{mig.BatchSize} QR kodu okundu. Telefonda sonrakine geç.";
                }
            }
            catch (Exception ex) { errors.Add(ex.Message); }
        }
        var parts = new List<string>();
        if (found > 0) parts.Add($"{found} hesap bulundu, {added} yeni hesap eklendi" + (found > added ? $" ({found - added} zaten vardı)." : "."));
        if (progress != "") parts.Add(progress);
        parts.AddRange(errors.Distinct());
        return string.Join("\n", parts);
    }

    void OnLock() { if (!App.Store.IsUnlocked) Dispatcher.Invoke(Close); }

    void ShowStatus(string s)
    {
        Status.Text = s;
        Status.Visibility = string.IsNullOrEmpty(s) ? Visibility.Collapsed : Visibility.Visible;
    }

    void ImportBitmap(Bitmap bmp)
    {
        var texts = QrReader.DecodeAll(bmp).Where(OtpImport.IsOtpText).ToList();
        ShowStatus(texts.Count == 0 ? "Görselde 2FA QR kodu bulunamadı." : HandleTexts(texts));
    }

    void Camera_Click(object sender, RoutedEventArgs e)
    {
        var cam = new CameraWindow { Owner = this };
        cam.ShowDialog();
        if (cam.Summary != "") ShowStatus(cam.Summary);
    }

    void File_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "Görseller|*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp|Tümü|*.*", Multiselect = true };
        if (dlg.ShowDialog(this) != true) return;
        var texts = new List<string>();
        foreach (var f in dlg.FileNames)
        {
            try { using var bmp = new Bitmap(f); texts.AddRange(QrReader.DecodeAll(bmp)); }
            catch (Exception ex) { ShowStatus(Path.GetFileName(f) + ": " + ex.Message); return; }
        }
        texts = texts.Where(OtpImport.IsOtpText).Distinct().ToList();
        ShowStatus(texts.Count == 0 ? "Seçilen görsellerde 2FA QR kodu bulunamadı." : HandleTexts(texts));
    }

    void Clipboard_Click(object sender, RoutedEventArgs e)
    {
        var img = System.Windows.Forms.Clipboard.GetImage();
        if (img == null)
        {
            var text = Clipboard.ContainsText() ? Clipboard.GetText() : "";
            ShowStatus(OtpImport.IsOtpText(text) ? HandleTexts(new[] { text }) : "Panoda görsel yok. (Win+Shift+S ile QR kodun ekran görüntüsünü alabilirsin.)");
            return;
        }
        using var bmp = new Bitmap(img);
        ImportBitmap(bmp);
    }

    void Screen_Click(object sender, RoutedEventArgs e)
    {
        Hide();
        System.Threading.Thread.Sleep(250);
        try
        {
            var texts = QrReader.ScanScreens().Where(OtpImport.IsOtpText).ToList();
            ShowStatus(texts.Count == 0 ? "Ekranda 2FA QR kodu bulunamadı." : HandleTexts(texts));
        }
        finally { Show(); Activate(); }
    }

    void Manual_Click(object sender, RoutedEventArgs e)
    {
        var secret = SecretBox.Text.Trim();
        try
        {
            if (OtpImport.IsOtpText(secret)) { ShowStatus(HandleTexts(new[] { secret })); }
            else
            {
                if (IssuerBox.Text.Trim() == "" && NameBox.Text.Trim() == "") { ShowStatus("Servis ya da hesap adı gir."); return; }
                var norm = Base32.Normalize(secret);
                if (Base32.Decode(norm).Length < 10) { ShowStatus("Anahtar çok kısa görünüyor."); return; }
                var acc = new Account { Issuer = IssuerBox.Text.Trim(), Name = NameBox.Text.Trim(), Secret = norm };
                ShowStatus(App.Store.AddRange(new[] { acc }) > 0 ? $"{acc.Title} eklendi. Şu anki kod: {Totp.Generate(acc)}" : "Bu anahtar zaten kayıtlı.");
            }
            IssuerBox.Text = NameBox.Text = SecretBox.Text = "";
        }
        catch (Exception ex) { ShowStatus(ex.Message); }
    }
}
