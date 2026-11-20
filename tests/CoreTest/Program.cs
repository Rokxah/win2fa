using System;
using Win2FA.Core;
int fail = 0;
void Check(string name, string got, string want) { var ok = got == want; if (!ok) fail++; Console.WriteLine((ok ? "OK   " : "FAIL ") + name + " => " + got + (ok ? "" : " (beklenen " + want + ")")); }
// RFC 6238 vektörleri (8 hane)
var s1 = Base32.Encode(System.Text.Encoding.ASCII.GetBytes("12345678901234567890"));
var s256 = Base32.Encode(System.Text.Encoding.ASCII.GetBytes("12345678901234567890123456789012"));
var s512 = Base32.Encode(System.Text.Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"));
var t = DateTimeOffset.FromUnixTimeSeconds(59);
Check("SHA1 t=59", Totp.Generate(new Account{Secret=s1,Digits=8}, t), "94287082");
Check("SHA256 t=59", Totp.Generate(new Account{Secret=s256,Digits=8,Algorithm="SHA256"}, t), "46119246");
Check("SHA512 t=59", Totp.Generate(new Account{Secret=s512,Digits=8,Algorithm="SHA512"}, t), "90693936");
Check("SHA1 t=1111111109", Totp.Generate(new Account{Secret=s1,Digits=8}, DateTimeOffset.FromUnixTimeSeconds(1111111109)), "07081804");
Check("SHA1 t=20000000000", Totp.Generate(new Account{Secret=s1,Digits=8}, DateTimeOffset.FromUnixTimeSeconds(20000000000)), "65353130");
// otpauth://
var a = OtpImport.ParseOtpAuth("otpauth://totp/GitHub:kullanici%40ornek.com?secret=jbsw%20y3dpehpk3pxp&issuer=GitHub");
Check("otpauth issuer", a.Issuer, "GitHub"); Check("otpauth name", a.Name, "kullanici@ornek.com"); Check("otpauth secret", a.Secret, "JBSWY3DPEHPK3PXP");
// Google Authenticator aktarma örneği
var list = OtpImport.FromText("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgACjr4JKK%2Bf%2F%2F%2F%2F8B", out var mig);
Check("migration count", list.Count.ToString(), "1");
Check("migration issuer", list[0].Issuer, "Example"); Check("migration name", list[0].Name, "alice@google.com");
Check("migration secret", list[0].Secret, "JBSWY3DPEHPK3PXP");
Check("migration batch", mig!.BatchIndex + "/" + mig.BatchSize, "0/1");
// Ana şifreli depo
var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "win2fa-test-" + Guid.NewGuid().ToString("N"));
Store.DirOverride = dir;
var st = new Store(); st.Load();
Check("yeni depo şifresiz", st.HasPassword.ToString(), "False");
st.SetupPassword("gizli123");
st.AddRange(new[]{ new Account{Issuer="Test", Name="a@b.c", Secret="JBSWY3DPEHPK3PXP"} });
var raw = System.IO.File.ReadAllBytes(Store.FilePath);
var unwrapped = System.Text.Encoding.UTF8.GetString(System.Security.Cryptography.ProtectedData.Unprotect(raw, System.Text.Encoding.UTF8.GetBytes("Win2FA.v1"), System.Security.Cryptography.DataProtectionScope.CurrentUser));
Check("diskte anahtar açıkta değil", unwrapped.Contains("JBSWY3DPEHPK3PXP").ToString(), "False");
var st2 = new Store(); st2.Load();
Check("şifre gerekli", (st2.HasPassword && !st2.IsUnlocked).ToString(), "True");
Check("yanlış şifre", st2.Unlock("yanlis").ToString(), "False");
Check("doğru şifre", st2.Unlock("gizli123").ToString(), "True");
Check("hesap çözüldü", st2.Accounts.Count + " " + st2.Accounts[0].Secret, "1 JBSWY3DPEHPK3PXP");
st2.Lock();
Check("kilitlenince bellek boş", st2.Accounts.Count.ToString(), "0");
st2.Unlock("gizli123");
Check("şifre değiştir (yanlış eski)", st2.ChangePassword("xx", "yeni456").ToString(), "False");
Check("şifre değiştir", st2.ChangePassword("gizli123", "yeni456").ToString(), "True");
var st3 = new Store(); st3.Load();
Check("yeni şifreyle açılır", (st3.Unlock("yeni456") && !new Func<bool>(() => { var s4 = new Store(); s4.Load(); return s4.Unlock("gizli123"); })()).ToString(), "True");
st3.EnableHello(Store.NewHelloChallenge(), new byte[]{1,2,3,4,5});
var h1 = new Store(); h1.Load();
Check("hello etkin", h1.HelloEnabled.ToString(), "True");
Check("hello yanlış imza", h1.UnlockWithHello(new byte[]{9,9,9}).ToString(), "False");
Check("hello doğru imza", h1.UnlockWithHello(new byte[]{1,2,3,4,5}).ToString(), "True");
Check("hello sonrası hesap", h1.Accounts.Count.ToString(), "1");
h1.AddRange(new[]{ new Account{Issuer="X", Secret="GEZDGNBVGY3TQOJQ"} });
var h2 = new Store(); h2.Load();
Check("kayıttan sonra hello hâlâ çalışır", (h2.UnlockWithHello(new byte[]{1,2,3,4,5}) && h2.Accounts.Count == 2).ToString(), "True");
h2.ChangePassword("yeni456", "son789");
Check("şifre değişince hello kapanır", h2.HelloEnabled.ToString(), "False");
System.IO.Directory.Delete(dir, true);
Console.WriteLine(fail == 0 ? "TÜMÜ GEÇTİ" : fail + " HATA");
return fail;
