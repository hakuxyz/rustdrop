#! vhs -- https://github.com/charmbracelet/vhs
# Regenerate the demo GIF:  vhs demo/demo.tape
# (rendered at 892x556 to match assets/demo.gif recorded via demo/render.py)

Output assets/demo.gif
Set width 900
Set height 560
Set font "JetBrains Mono"
Set theme "Catppuccin Mocha"
Set fontSize 15

# Terminal 1 – receiver (background)
Spawn `rustdrop receive -o /tmp/demo-rx --yes --port 9901 --timeout 30`
Sleep 1s

# Terminal 2 – sender: auto-discovery, compression, rate limit, hashes
Type `rustdrop send --compress --limit 24M --verbose demo-src`
Enter
Sleep 2.5s
Sleep 3s
Type `sha256sum /tmp/demo-rx/demo-src/photos/launch-telemetry.bin`
Enter
Sleep 1.5s
