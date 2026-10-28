#!/usr/bin/env python3
"""Render a RustDrop terminal demo GIF from two `script` recordings.

Recorded like this (see demo/demo.tape for the VHS equivalent):

    script -T rx.timing -qefc "stty cols 96 rows 18; rustdrop receive -o /tmp/demo-rx --yes --port 9901" rx.raw
    script -T tx.timing -qefc "stty cols 96 rows 18; rustdrop send --compress --limit 24M --verbose demo-src" tx.raw

Then:

    python3 demo/render.py demo-rec assets/demo.gif
"""

from __future__ import annotations

import sys
from pathlib import Path

import pyte
from PIL import Image, ImageDraw, ImageFont

COLS = 96
ROWS = 14
CELL_W = 9
CELL_H = 17
FONT_SIZE = 15
FPS = 8
PALETTE_COLORS = 128

BG = "#11111b"
FG = "#cdd6f4"
CURSOR = "#89b4fa"

MONO = "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf"
MONO_BOLD = "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Bold.ttf"
LABEL = "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Bold.ttf"

NAMED = {
    "black": "#1e1e2e",
    "red": "#f38ba8",
    "green": "#a6e3a1",
    "yellow": "#f9e2af",
    "blue": "#89b4fa",
    "magenta": "#cba6f7",
    "cyan": "#94e2d5",
    "white": "#bac2de",
    "brightblack": "#6c7086",
    "brightred": "#f38ba8",
    "brightgreen": "#a6e3a1",
    "brightyellow": "#f9e2af",
    "brightblue": "#89b4fa",
    "brightmagenta": "#cba6f7",
    "brightcyan": "#94e2d5",
    "brightwhite": "#a6adc8",
}


def parse_recording(timing: Path, raw: Path) -> list[tuple[float, bytes]]:
    """Parse `script --log-timing` output into (timestamp, bytes) events."""
    events: list[tuple[float, bytes]] = []
    blob = raw.read_bytes()
    # util-linux `script` writes a "Script started on ..." banner into the log;
    # drop it so the pane starts on real program output.
    skip = 0
    if blob.startswith((b"Skript gestartet", b"Script started")):
        nl = blob.find(b"\n")
        skip = nl + 1 if nl != -1 else 0
    t = 0.0
    off = 0
    for line in timing.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        delay_s, count_s = line.split()
        t += float(delay_s)
        count = int(count_s)
        chunk = blob[off : off + count]
        off += count
        if skip:
            cut = min(skip, len(chunk))
            chunk = chunk[cut:]
            skip -= cut
            if not chunk:
                continue
        events.append((t, chunk))
    return events


def color_of(name: str | None) -> str:
    if not name or name == "default":
        return FG
    if name.startswith("#"):
        return name
    return NAMED.get(name, FG)


class Pane:
    def __init__(self, events: list[tuple[float, bytes]], offset: float) -> None:
        self.events = events
        self.offset = offset
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream = pyte.ByteStream(self.screen)
        self.cursor = 0

    def seek(self, t: float) -> None:
        local = t - self.offset
        while self.cursor < len(self.events) and self.cursor_time() <= local:
            self.stream.feed(self.events[self.cursor][1])
            self.cursor += 1

    def cursor_time(self) -> float:
        return self.events[self.cursor][0] if self.cursor < len(self.events) else float("inf")


def draw_pane(
    draw: ImageDraw.ImageDraw,
    pane: Pane,
    origin: tuple[int, int],
    font,
    font_bold,
) -> None:
    ox, oy = origin
    screen = pane.screen
    for y in range(ROWS):
        row = screen.buffer[y]
        x = 0
        while x < COLS:
            cell = row[x]
            style = (cell.fg, cell.bold, cell.reverse)
            run: list[str] = []
            while x < COLS:
                c = row[x]
                if (c.fg, c.bold, c.reverse) != style:
                    break
                run.append(c.data if c.data else " ")
                x += 1
            text = "".join(run)
            if not text.strip():
                continue
            fnt = font_bold if style[1] else font
            fill = color_of(style[0])
            if style[2]:
                draw.rectangle(
                    [ox + (x - len(run)) * CELL_W, oy + y * CELL_H,
                     ox + x * CELL_W, oy + (y + 1) * CELL_H],
                    fill=fill,
                )
                fill = BG
            draw.text((ox + (x - len(run)) * CELL_W, oy + y * CELL_H + 1), text, font=fnt, fill=fill)



def render(
    rx_events: list[tuple[float, bytes]],
    tx_events: list[tuple[float, bytes]],
    out: Path,
    label_font,
    label_h: int = 26,
) -> None:
    rx = Pane(rx_events, 0.0)
    tx = Pane(tx_events, 1.2)
    duration = max(
        rx_events[-1][0] if rx_events else 0,
        (tx_events[-1][0] if tx_events else 0) + 1.2,
    ) + 0.4

    margin = 14
    pane_w = COLS * CELL_W + margin * 2
    pane_h = ROWS * CELL_H + margin
    canvas_w = pane_w
    canvas_h = label_h + pane_h + label_h + pane_h

    frames: list[Image.Image] = []
    steps = int(duration * FPS) + 1
    for i in range(steps):
        t = i / FPS
        rx.seek(t)
        tx.seek(t)
        img = Image.new("RGB", (canvas_w, canvas_h), BG)
        draw = ImageDraw.Draw(img)

        y = 0
        for pane, title, accent in (
            (rx, "receiver", "#a6e3a1"),
            (tx, "sender", "#89b4fa"),
        ):
            draw.ellipse([margin, y + 9, margin + 8, y + 17], fill=accent)
            draw.text((margin + 14, y + 2), title, font=label_font, fill="#6c7086")
            draw_pane(draw, pane, (margin, y + label_h), _font(MONO, FONT_SIZE), _font(MONO_BOLD, FONT_SIZE))
            y += label_h + pane_h

        frames.append(img.convert("P", palette=Image.ADAPTIVE, colors=PALETTE_COLORS))

    out.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=int(1000 / FPS),
        loop=0,
        optimize=True,
    )
    last = frames[-1].convert("RGB")
    last.save(out.with_suffix(".png"))
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KiB, {len(frames)} frames, {duration:.1f}s)")


_cache: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def _font(path: str, size: int) -> ImageFont.FreeTypeFont:
    key = (path, size)
    if key not in _cache:
        _cache[key] = ImageFont.truetype(path, size)
    return _cache[key]


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    rec = Path(sys.argv[1])
    out = Path(sys.argv[2])
    rx = parse_recording(rec / "rx.timing", rec / "rx.raw")
    tx = parse_recording(rec / "tx.timing", rec / "tx.raw")
    render(rx, tx, out, _font(LABEL, 13))


if __name__ == "__main__":
    main()
