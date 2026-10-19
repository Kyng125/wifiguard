"""Write one pcap per test scenario into samples/pcaps/ (fabricated frames matching the demo database).

    python tools/make_sample_pcaps.py
    flask --app wifiguard seed-demo --reset
    flask --app wifiguard replay-pcap samples/pcaps/deauth.pcap
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wifiguard.engine import synthetic  # noqa: E402

out = Path(__file__).resolve().parent.parent / "samples" / "pcaps"
out.mkdir(parents=True, exist_ok=True)
start = time.time()
for name, build in synthetic.SCENARIOS.items():
    for written in synthetic.write_pcap(str(out / f"{name}.pcap"), build(start)):
        print("wrote", written)
