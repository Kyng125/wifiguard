# Live capture (the original Phase 3), kept as a backup plan

**Status: not built.** Phase 3 was changed to *portable replay mode* (see `docs/engine.md`) because the project runs on
Windows laptops, may move between machines, and has no monitor-mode adapter. This file keeps the original plan so
live capture can be added later without rediscovering anything. Nothing below has been implemented or tested.

## What live capture needs that replay does not

| Need | Why |
| --- | --- |
| **Linux** host (or a Linux VM with the adapter passed through) | Monitor mode and channel control are dependable only there. macOS is limited; Windows is practically unavailable. |
| **A monitor-mode-capable adapter** | A normal Wi-Fi radio only hears its own connection. The adapter's chipset and driver decide whether it supports monitor mode and 5 GHz. While in monitor mode it cannot be used for ordinary internet. |
| **Root privileges** | To change the interface mode and open a raw socket. |
| **Something to detect** | A lab router you own and a second device to generate test activity. Run attacks only on your own equipment. |

To tell the next session what you have, run on the Linux machine and paste the output:

```
cat /etc/os-release
uname -r
lsusb
iw list | grep -A12 "Supported interface modes"
iw list | grep -i "MHz \[" | head -40
ip link
```

## Original scope

1. **Monitor-mode setup** as a small separate script, not mixed into the capture code. Typical commands:
   `ip link set wlan1 down`, `iw dev wlan1 set type monitor`, `ip link set wlan1 up`, `iw dev wlan1 set channel 6`.
   NetworkManager often grabs the interface: `nmcli device set wlan1 managed no` (distro specific).
2. **Channel handling**: locked to the first channel by default (`channel_mode = locked`), optional hopping through
   `channels` every `channel_dwell_ms` (all three settings already exist and are validated by the API). Hopping means
   frames on other channels are missed, which the report's limitations section should state.
3. **Capture thread**: Scapy `sniff(iface=..., store=False, prn=..., filter=<BPF>)` feeding `Processor.process()` and
   then the existing `Pipeline.handle()`. Measure on the real host: Scapy's own dissection was about 2,300 frames/s on
   the build machine while parsing plus rules ran about 16,000/s, so Scapy is the bottleneck. Drop and count under load
   instead of letting a queue grow without limit.
4. **Second source for ARP**: an Ethernet or managed-mode interface (`arp_interface`), because ARP is not visible in
   monitor mode on a protected network without the key. Its link type differs from 802.11.
5. **Runtime state**: monitor snapshots, frame feed, engine state.

## What already exists and can be reused as is

- `engine/processor.py`, `rules.py`, `engine.py`, `pipeline.py`: nothing about them depends on where frames come from.
- `engine/runtime.py`: `write_snapshot`, `_Meter` (counters and packets per second) and `_Feed` (bounded frame sampling) are
  source-independent. The settings `monitor_interface`, `arp_interface`, `channels`, `channel_mode` and
  `channel_dwell_ms` and the `monitor_snapshots` and `frame_samples` tables are in place.
- The Dashboard already reads engine state, packets per second and the capture sources from the snapshots.

## What would have to be written

- A live frame source (sniff callback or thread) that produces `Frame` objects with the real capture time.
- The monitor-mode setup script and its documentation per distro and adapter.
- A refactor of `ReplayRuntime._run`: its loop body (meter, pipeline, feed, snapshot) is written around `ReplayMixer`;
  extract it into a function that consumes any iterator of frames, then give the live source its own thread.
- Source selection: a `source` setting or start option (`replay` | `live`), and `/api/monitor/status` reporting
  `source.kind = "live"`. The `source` object and per-source `mode` field already exist for this.
- Drop accounting, a stop procedure that restores the adapter to managed mode, and a short privilege-separation note
  (the capture process needs root, the web server should not).
- Tests: the sniffing itself cannot run in CI. Test the source with a fake sniffer and the setup script by parsing
  its command output, then run the lab scenarios from Phase 4 on real hardware.

## How to return to it

1. Collect the adapter and distro details above.
2. Ask for "live capture (docs/live-capture-backup.md)" and say whether the host is a Linux machine or a VM.
3. Replay mode keeps working alongside it: the same engine, API and dashboard, with a different source.
