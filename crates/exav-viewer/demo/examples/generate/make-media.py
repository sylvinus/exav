#!/usr/bin/env python3
"""Writes the demo's audio and video examples into ../files/media/.

    python3 -I make-media.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. The tune is
composed and synthesised here (a four-voice canon on a pentatonic scale, sine
waves with a few harmonics and an envelope); the picture is ffmpeg's own
"testsrc2" pattern with a clock.

Needs: Python 3, numpy, and ffmpeg (with libx264, libvpx-vp9, libopus,
libvorbis, libmp3lame and the native aac and flac encoders). The files that
use a missing encoder are skipped.
"""
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import wave

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "media")
os.makedirs(OUT, exist_ok=True)
RATE = 8000
SCALE = [0, 2, 4, 7, 9]  # a major pentatonic scale
MELODY = [0, 2, 4, 2, 3, 4, 6, 4, 2, 0, 1, 2, 4, 3, 2, 1]  # degrees; the scale repeats over octaves


def freq(degree, base=261.63):
    octave, step = divmod(degree, len(SCALE))
    return base * 2 ** ((SCALE[step] + 12 * octave) / 12)


def voice(delay_beats, octave, beat=0.3, seconds=8.4):
    t = np.arange(int(RATE * seconds)) / RATE
    out = np.zeros_like(t)
    for i, degree in enumerate(MELODY):
        start = (delay_beats + i) * beat
        if start >= seconds:
            break
        f = freq(degree + octave * len(SCALE))
        n = np.clip(t - start, 0, None)
        env = (t >= start) * np.exp(-n * 5.0) * np.minimum(n / 0.01, 1.0)
        out += env * (np.sin(2 * math.pi * f * t) + 0.35 * np.sin(4 * math.pi * f * t) + 0.12 * np.sin(6 * math.pi * f * t))
    return out


def tune():
    mix = voice(0, 0) + voice(4, 1) * 0.8 + voice(8, 0) * 0.7 + voice(12, -1) * 0.9
    mix /= np.abs(mix).max() * 1.1
    fade = np.minimum(1.0, (len(mix) - np.arange(len(mix))) / (RATE * 0.5))
    return (mix * fade * 32000).astype("<i2")


def ffmpeg(*args):
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args], check=True)


samples = tune()
with tempfile.TemporaryDirectory() as tmp:
    wav = os.path.join(tmp, "tune.wav")
    with wave.open(wav, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(samples.tobytes())
    shutil.copy(wav, os.path.join(OUT, "canon.wav"))
    if shutil.which("ffmpeg"):
        flags = ["-map_metadata", "-1", "-fflags", "+bitexact", "-flags:a", "+bitexact"]
        ffmpeg("-i", wav, *flags, "-c:a", "libmp3lame", "-b:a", "24k", "-id3v2_version", "0", "-write_id3v1", "0", os.path.join(OUT, "canon.mp3"))
        ffmpeg("-i", wav, *flags, "-c:a", "flac", "-compression_level", "8", os.path.join(OUT, "canon.flac"))
        ffmpeg("-i", wav, *flags, "-c:a", "libvorbis", "-q:a", "2", os.path.join(OUT, "canon.ogg"))
        ffmpeg("-i", wav, *flags, "-c:a", "libopus", "-b:a", "16k", os.path.join(OUT, "canon.opus"))
        ffmpeg("-i", wav, *flags, "-c:a", "aac", "-b:a", "24k", "-movflags", "+faststart", os.path.join(OUT, "canon.m4a"))
        video = ["-f", "lavfi", "-i", "testsrc2=size=256x192:rate=12:duration=4", "-i", wav, "-t", "4", "-shortest"]
        ffmpeg(*video, *flags, "-c:v", "libx264", "-profile:v", "baseline", "-pix_fmt", "yuv420p", "-crf", "34", "-preset", "veryslow", "-c:a", "aac", "-b:a", "24k", "-movflags", "+faststart", os.path.join(OUT, "testcard.mp4"))
        ffmpeg(*video, *flags, "-c:v", "libvpx-vp9", "-crf", "46", "-b:v", "0", "-pix_fmt", "yuv420p", "-c:a", "libopus", "-b:a", "16k", os.path.join(OUT, "testcard.webm"))
