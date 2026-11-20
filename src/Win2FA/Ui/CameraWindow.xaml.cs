using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Win2FA.Core;
using Windows.Devices.Enumeration;
using Windows.Graphics.Imaging;
using Windows.Media.Capture;
using Windows.Media.Capture.Frames;
using Windows.Media.MediaProperties;

namespace Win2FA.Ui;

/// <summary>
/// Canlı kamera önizlemesi (MediaFrameReader, ~30 fps) ve arka planda QR okuma.
/// Önizleme ile QR çözme birbirini beklemez: çözücü meşgulse yeni kareler yalnızca ekrana çizilir.
/// </summary>
public partial class CameraWindow : Window
{
    MediaCapture? _capture;
    MediaFrameReader? _reader;
    WriteableBitmap? _bitmap;
    readonly HashSet<string> _seen = new();
    List<DeviceInformation> _devices = new();
    int _rendering, _decoding;     // 0/1 bayrakları (Interlocked)
    long _lastDecodeTicks;
    volatile bool _closing;
    public string Summary { get; private set; } = "";

    public CameraWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await InitAsync();
        Closing += (_, _) => _closing = true;
        Closed += async (_, _) => await StopAsync();
    }

    async Task InitAsync()
    {
        _devices = (await DeviceInformation.FindAllAsync(DeviceClass.VideoCapture)).ToList();
        if (_devices.Count == 0)
        {
            Hint.Text = "Kamera bulunamadı.\nQR kodun fotoğrafını \"Görsel dosyası seç\" ile de yükleyebilirsin.";
            return;
        }
        foreach (var d in _devices) Cameras.Items.Add(d.Name);
        Cameras.SelectedIndex = 0; // SelectionChanged → StartAsync
    }

    async void Cameras_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (Cameras.SelectedIndex < 0) return;
        await StopAsync();
        await StartAsync(_devices[Cameras.SelectedIndex].Id);
    }

    async Task StartAsync(string deviceId)
    {
        try
        {
            Hint.Text = "Kamera açılıyor…";
            Hint.Visibility = Visibility.Visible;
            _capture = new MediaCapture();
            await _capture.InitializeAsync(new MediaCaptureInitializationSettings
            {
                VideoDeviceId = deviceId,
                StreamingCaptureMode = StreamingCaptureMode.Video,
                MemoryPreference = MediaCaptureMemoryPreference.Cpu,
                SharingMode = MediaCaptureSharingMode.ExclusiveControl,
            });

            var source = _capture.FrameSources.Values
                .Where(s => s.Info.SourceKind == MediaFrameSourceKind.Color)
                .OrderBy(s => s.Info.MediaStreamType == Windows.Media.Capture.MediaStreamType.VideoPreview ? 0 : 1)
                .FirstOrDefault() ?? throw new InvalidOperationException("Renkli görüntü kaynağı yok.");

            // ~720p ve en yüksek kare hızına yakın bir biçim seç (QR için yeterli, işlemciyi yormaz).
            var format = source.SupportedFormats
                .Where(f => f.VideoFormat.Width <= 1280 && f.VideoFormat.Width >= 480)
                .OrderByDescending(f => FrameRate(f) >= 24 ? 1 : 0)
                .ThenByDescending(f => f.VideoFormat.Width)
                .ThenByDescending(FrameRate)
                .FirstOrDefault();
            if (format != null)
            {
                try { await source.SetFormatAsync(format); } catch { /* bazı kameralar reddeder; varsayılanla devam */ }
            }

            _reader = await _capture.CreateFrameReaderAsync(source, MediaEncodingSubtypes.Bgra8);
            _reader.AcquisitionMode = MediaFrameReaderAcquisitionMode.Realtime;
            _reader.FrameArrived += OnFrameArrived;
            var status = await _reader.StartAsync();
            if (status != MediaFrameReaderStartStatus.Success)
                Hint.Text = "Kamera başlatılamadı (" + status + "). Kamera başka bir uygulamada açık olabilir.";
        }
        catch (UnauthorizedAccessException)
        {
            Hint.Text = "Kamera izni yok.\nAyarlar → Gizlilik ve güvenlik → Kamera → \"Masaüstü uygulamalarının kameraya erişmesine izin ver\" açık olmalı.";
        }
        catch (Exception ex) { Hint.Text = "Kamera açılamadı: " + ex.Message; }
    }

    static double FrameRate(MediaFrameFormat f) =>
        f.FrameRate.Denominator == 0 ? 0 : (double)f.FrameRate.Numerator / f.FrameRate.Denominator;

    void OnFrameArrived(MediaFrameReader sender, MediaFrameArrivedEventArgs args)
    {
        if (_closing) return;
        using var frame = sender.TryAcquireLatestFrame();
        var sb = frame?.VideoMediaFrame?.SoftwareBitmap;
        if (sb == null) return;

        bool wantDecode = Volatile.Read(ref _decoding) == 0 &&
                          DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastDecodeTicks) > TimeSpan.TicksPerMillisecond * 120;
        bool wantRender = Volatile.Read(ref _rendering) == 0;
        if (!wantDecode && !wantRender) return;   // ekran ve çözücü meşgul: kareyi atla

        SoftwareBitmap? bgra = null;
        try
        {
            bgra = sb.BitmapPixelFormat == BitmapPixelFormat.Bgra8 && sb.BitmapAlphaMode != BitmapAlphaMode.Straight
                ? sb
                : SoftwareBitmap.Convert(sb, BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied);
            int w = bgra.PixelWidth, h = bgra.PixelHeight;
            var pixels = new byte[w * h * 4];
            bgra.CopyToBuffer(pixels.AsBuffer());

            if (wantRender && Interlocked.Exchange(ref _rendering, 1) == 0)
            {
                Dispatcher.BeginInvoke(() =>
                {
                    try
                    {
                        if (_closing) return;
                        if (_bitmap == null || _bitmap.PixelWidth != w || _bitmap.PixelHeight != h)
                        {
                            _bitmap = new WriteableBitmap(w, h, 96, 96, PixelFormats.Bgra32, null);
                            Preview.Source = _bitmap;
                        }
                        _bitmap.WritePixels(new Int32Rect(0, 0, w, h), pixels, w * 4, 0);
                        Hint.Visibility = Visibility.Collapsed;
                    }
                    finally { Volatile.Write(ref _rendering, 0); }
                });
            }

            if (wantDecode && Interlocked.Exchange(ref _decoding, 1) == 0)
            {
                Interlocked.Exchange(ref _lastDecodeTicks, DateTime.UtcNow.Ticks);
                Task.Run(() =>
                {
                    try
                    {
                        var texts = QrReader.DecodeBgra(pixels, w, h);
                        var fresh = texts.Where(t => OtpImport.IsOtpText(t) && _seen.Add(t)).ToList();
                        if (fresh.Count > 0 && !_closing)
                            Dispatcher.BeginInvoke(() =>
                            {
                                Summary = ImportWindow.HandleTexts(fresh);
                                Status.Text = Summary;
                                System.Media.SystemSounds.Asterisk.Play();
                            });
                    }
                    catch { }
                    finally { Volatile.Write(ref _decoding, 0); }
                });
            }
        }
        finally
        {
            if (bgra != null && !ReferenceEquals(bgra, sb)) bgra.Dispose();
        }
    }

    async Task StopAsync()
    {
        var reader = _reader;
        _reader = null;
        if (reader != null)
        {
            reader.FrameArrived -= OnFrameArrived;
            try { await reader.StopAsync(); } catch { }
            reader.Dispose();
        }
        _capture?.Dispose();
        _capture = null;
    }

    void Done_Click(object sender, RoutedEventArgs e) => Close();
}
