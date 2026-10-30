#! vhs -- https://github.com/charmbracelet/vhs
# Regenerate the demo GIF:  vhs demo/demo.tape
# The committed assets/demo.gif was recorded with script(1) + demo/render.py
# (same scenario: interrupt a transfer, re-send, resume with proof).
#
# Prerequisite:
#   mkdir -p /tmp/demo-src
#   dd if=/dev/urandom of=/tmp/demo-src/launch-telemetry.bin bs=1M count=40

Output assets/demo.gif
Set width 900
Set height 560
Set font "JetBrains Mono"
Set theme "Catppuccin Mocha"
Set fontSize 15

# Terminal 1 - receiver: stays up, keeps the .part leftovers
Spawn `rustdrop receive -o /tmp/demo-rx --yes --keep-open --port 9901 --timeout 60`
Sleep 1s

# Terminal 2 - sender: killed mid-transfer, then sent again; the second run
# skips the verified prefix ("skipping 8.7 MiB the receiver already has")
Type `bash -c 'timeout -s INT 2.5 rustdrop send --limit 8M --to 127.0.0.1:9901 /tmp/demo-src; sleep 1.5; rustdrop send --limit 8M --to 127.0.0.1:9901 /tmp/demo-src'`
Enter
Sleep 16s
