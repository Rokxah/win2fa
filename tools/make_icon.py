# Win2FA simgesi: mavi yuvarlak kare + beyaz kilit. app.ico (çok boyutlu) ve icon.png (512) üretir.
import sys
from PIL import Image, ImageDraw

def draw(size):
    s = size / 512
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=int(112 * s), fill=(76, 141, 255, 255))
    # gövde
    d.rounded_rectangle([int(140 * s), int(230 * s), int(372 * s), int(410 * s)], radius=int(34 * s), fill=(255, 255, 255, 255))
    # halka
    w = max(2, int(36 * s))
    d.arc([int(178 * s), int(110 * s), int(334 * s), int(290 * s)], 180, 360, fill=(255, 255, 255, 255), width=w)
    d.rectangle([int(178 * s), int(198 * s), int(178 * s) + w, int(240 * s)], fill=(255, 255, 255, 255))
    d.rectangle([int(334 * s) - w, int(198 * s), int(334 * s), int(240 * s)], fill=(255, 255, 255, 255))
    # anahtar deliği
    d.ellipse([int(236 * s), int(286 * s), int(276 * s), int(326 * s)], fill=(76, 141, 255, 255))
    d.rectangle([int(248 * s), int(310 * s), int(264 * s), int(362 * s)], fill=(76, 141, 255, 255))
    return img

out_ico, out_png = sys.argv[1], sys.argv[2]
big = draw(512)
big.save(out_png)
big.save(out_ico, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("ok")
