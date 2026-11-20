using System.Windows;
using System.Windows.Input;
using Win2FA.Core;

namespace Win2FA.Ui;

public partial class EditWindow : Window
{
    readonly Account _account;

    public EditWindow(Account account)
    {
        InitializeComponent();
        _account = account;
        IssuerBox.Text = account.Issuer;
        NameBox.Text = account.Name;
        Info.Text = $"{account.Algorithm} · {account.Digits} hane · {account.Period} sn" +
                    (account.UseCount > 0 ? $" · {account.UseCount} kez kullanıldı" : "");
        Loaded += (_, _) => { IssuerBox.Focus(); IssuerBox.SelectAll(); };
        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); };
    }

    void Box_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Save_Click(sender, e);
        else if (e.Key == Key.Escape) Close();
    }

    void Save_Click(object sender, RoutedEventArgs e)
    {
        var issuer = IssuerBox.Text.Trim();
        var name = NameBox.Text.Trim();
        if (issuer == "" && name == "")
        {
            MessageBox.Show(this, "Görünen ad ile hesap alanlarından en az biri dolu olmalı.", "Win2FA", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        _account.Issuer = issuer;
        _account.Name = name;
        App.Store.Save();
        DialogResult = true;
    }

    void Delete_Click(object sender, RoutedEventArgs e)
    {
        var ok = MessageBox.Show(this,
            $"\"{_account.Title}\"" + (_account.Subtitle != "" ? $" ({_account.Subtitle})" : "") + " silinsin mi?\n\n" +
            "Bu hesabın gizli anahtarı Win2FA'dan kalıcı olarak silinir, geri alınamaz. " +
            "Telefondaki Google Authenticator'da kopyası yoksa bu servise giriş yapamayabilirsin.",
            "Hesabı sil", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (ok != MessageBoxResult.Yes) return;
        App.Store.Remove(_account);
        DialogResult = true;
    }

    void Cancel_Click(object sender, RoutedEventArgs e) => Close();
}
