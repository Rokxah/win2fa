using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Linq;
using System.Windows.Forms;
using ZXing;
using ZXing.Common;
using ZXing.Windows.Compatibility;

namespace Win2FA.Core;

public static class QrReader
{
    static BarcodeReader NewReader() => new()
    {
        AutoRotate = true,
        Options = new DecodingOptions { TryHarder = true, PossibleFormats = new[] { BarcodeFormat.QR_CODE } },
    };

    /// <summary>Kameradan gelen ham BGRA karesini çözer.</summary>
    public static List<string> DecodeBgra(byte[] pixels, int width, int height)
    {
        var reader = new BarcodeReaderGeneric
        {
            AutoRotate = false,
            Options = new DecodingOptions { TryHarder = true, PossibleFormats = new[] { BarcodeFormat.QR_CODE } },
        };
        var source = new RGBLuminanceSource(pixels, width, height, RGBLuminanceSource.BitmapFormat.BGRA32);
        var result = reader.Decode(source);
        return result == null ? new List<string>() : new List<string> { result.Text };
    }

    public static List<string> DecodeAll(Bitmap bmp)
    {
        var results = NewReader().DecodeMultiple(bmp);
        return results?.Select(r => r.Text).Distinct().ToList() ?? new List<string>();
    }

    /// <summary>Tüm ekranları tarar.</summary>
    public static List<string> ScanScreens()
    {
        var found = new List<string>();
        foreach (var screen in Screen.AllScreens)
        {
            var b = screen.Bounds;
            using var bmp = new Bitmap(b.Width, b.Height, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(bmp))
                g.CopyFromScreen(b.Left, b.Top, 0, 0, b.Size);
            found.AddRange(DecodeAll(bmp));
        }
        return found.Distinct().ToList();
    }
}
