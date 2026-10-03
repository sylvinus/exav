#!/usr/bin/env python3
"""Writes the reference images: one synthetic picture in every format and mode
the hash reads, small, and released into the public domain (CC0).

`expected.txt` then holds, per file, the hash of `sigtool --fuzzy-img`
(ClamAV 1.5.4) and of Python `imagehash.phash` (4.3.2, Pillow 12.3.0):

    python3 generate.py
    for f in img/*; do printf '%s ' "$(basename $f)"; sigtool --fuzzy-img $f; done
    python3 -c 'import imagehash, PIL.Image, sys; ...'

Needs Pillow and numpy.
"""
import os
import numpy
from PIL import Image

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'img')
os.makedirs(OUT, exist_ok=True)

# Smooth gradients and rings in every channel, odd dimensions so that the
# resize has to weigh partial pixels.
w, h = 97, 61
y, x = numpy.mgrid[0:h, 0:w].astype(float)
r = 127.5 + 127.5 * numpy.sin(x / 7.0 + y / 13.0)
g = 127.5 + 127.5 * numpy.cos(numpy.hypot(x - 40, y - 25) / 5.0)
b = 255.0 * x / (w - 1) * (1 - y / (h - 1))
rgb = Image.fromarray(numpy.dstack([r, g, b]).round().astype('uint8'), 'RGB')
a = numpy.asarray(rgb.convert('RGBA')).copy()
a[..., 3] = (255 * x / (w - 1)).round().astype('uint8')
rgba = Image.fromarray(a, 'RGBA')
rgb16 = (numpy.asarray(rgb).astype('uint16') * 257 + 77).astype('>u2')


def save(im, name, **kw):
    im.save(os.path.join(OUT, name), **kw)


save(rgb, 'rgb.png')
save(rgba, 'rgba.png')
save(rgb.convert('L'), 'l.png')
save(rgb.convert('LA'), 'la.png')
save(rgb.convert('P', palette=Image.Palette.ADAPTIVE, colors=100), 'p.png')
save(rgb.convert('P', palette=Image.Palette.ADAPTIVE, colors=32), 'p_trns.png', transparency=3)
save(rgb.convert('1'), 'bilevel.png')
save(rgb.convert('L').convert('I;16'), 'i16.png')
save(rgb, 'rgb.gif')
save(rgb.convert('P', palette=Image.Palette.ADAPTIVE, colors=32), 'trns.gif', transparency=3)
save(rgb, 'rgb.bmp')
save(rgba, 'rgba.bmp')
save(rgb.convert('P', palette=Image.Palette.ADAPTIVE), 'p.bmp')
save(rgb.convert('1'), 'bilevel.bmp')
save(rgb, 'rgb.jpg', quality=90)
save(rgb.convert('L'), 'l.jpg', quality=90)
save(rgb, 'rgb.tif')
save(rgb, 'lzw.tif', compression='tiff_lzw')
save(rgb, 'deflate.tif', compression='tiff_adobe_deflate')
save(rgb.convert('L'), 'l.tif')
save(rgb.convert('CMYK'), 'cmyk.tif')
save(rgb, 'lossless.webp', lossless=True)
save(rgba, 'rgba.webp', lossless=True)
save(rgb, 'lossy.webp', quality=80)
save(rgba.resize((48, 48)), 'rgba.ico', sizes=[(48, 48)])
save(rgba.resize((32, 32)), 'bmp.ico', sizes=[(32, 32)], bitmap_format='bmp')
save(rgb, 'rgb.ppm')
save(rgb.convert('L'), 'l.pgm')
save(rgb.convert('1'), 'bilevel.pbm')
with open(os.path.join(OUT, 'rgb16.ppm'), 'wb') as f:
    f.write(f'P6 {w} {h} 65535\n'.encode() + rgb16.tobytes())
save(rgb, 'rgb.qoi')
save(rgba, 'rgba.qoi')
