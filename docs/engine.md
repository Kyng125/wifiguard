# Detection engine (Phases 2 and 3)

Implements report Sections 3.6.2 (packet processor), 3.6.3 (detection engine) and 3.10 (the four rules).

Frames reach the engine from a **source**. Today the source is recorded pcap files replayed at their original pace
(*replay mode*, below): it runs on any laptop with no adapter. Live capture from a radio is documented as a backup plan in
`live-capture-backup.md`; it would be a second source feeding the same engine.

```
raw packet --processor.parse()--> Frame --DetectionEngine.process()--> detections + observations
                                                                          |
                                         pipeline.Pipeline  -->  events.create_event()  (alerts, cool-down merging)
                                                            -->  observed_access_points / observed_devices / arp_bindings
```

`wifiguard/engine/`

| File | Role | Needs database |
| --- | --- | --- |
| `processor.py` | Scapy packet -> `Frame` (addresses, SSID, channel, signal, security mode, reason code, ARP pairs). Never keeps payloads. | no |
| `rules.py` | The four rules, each a small stateful object. | no |
| `engine.py` | Runs the rules, updates the in-memory reference, returns `Result(detections, observations)`. | no |
| `reference.py` | In-memory authorised lists, observed sets and ARP table; `load()` and `reload_inventory()` read the database. | only `load` |
| `pipeline.py` | Writes observations and hands detections to `events.create_event`; `replay()` for pcap files. | yes (app context) |
| `synthetic.py` | Fabricated frames and the five test scenarios. | no |
| `sources.py` | Scenario files and `ReplayMixer`: releases recorded frames at their original pace, layers triggered scenarios on top. | no |
| `runtime.py` | `ReplayRuntime`: the background thread that runs source -> pipeline and writes the monitor snapshots and frame feed. | yes (app context) |

## Rules

All windows and cool-downs use the frame's capture timestamp, so a pcap replays exactly like live capture.

| Rule | Fires when | Evidence | Cool-down |
| --- | --- | --- | --- |
| Deauthentication flood | `threshold` (100) deauthentication frames from one BSSID within `windowSeconds` (10), window edges inclusive | `frameCount, windowSeconds, threshold, reasonCode, distinctTargets` | 60 s per BSSID |
| ARP conflict | An ARP **reply** gives a known IP a different MAC | `ip, previousMac, newMac` | 60 s per IP |
| Rogue AP | A beacon or probe response with a known or institutional SSID from a BSSID that is not authorised; or an authorised BSSID advertising **weaker** security than registered | `ssid, channel, securityMode, reason, authorisedSecurityModes?, signal?` | 300 s per BSSID |
| Unrecognised device | First association, authentication or data frame from a MAC that is neither authorised nor already observed, on an **authorised** BSSID | `associatedBssid, randomisedAddress` | 300 s per MAC |

Keys listed first are the ones `events.REQUIRED_EVIDENCE` demands; keys with `?` or beyond them are extras.
A rule that keeps matching during a sustained event fires once per cool-down; the event manager merges those matches into
one alert and counts `occurrences`.

## Decisions to review

These go beyond or refine what Section 3.10 states. Each is small and changeable.

1. **Deauthentication counts only deauthentication frames**, not disassociation (constructor flag `include_disassociation` exists, default off). Section 2.2.10 mentions both; 3.10.1 specifies deauthentication.
2. **ARP alerts come from replies only**, as the pseudocode says. Requests teach a binding for an IP not seen before but never overwrite or alert. ARP probes (0.0.0.0), link-local, broadcast and all-zero addresses are ignored.
3. **Unrecognised-device alerts apply to clients of our own authorised access points only.** A monitor-mode adapter hears every network on the channel; alerting on neighbours' phones would flood the dashboard, and storing them would record strangers' devices. Consequence: until at least one authorised access point is registered, this rule is silent. The dashboard API reports this as the `no_authorised_aps` warning (see "Authorising your access points").
4. **Rogue-AP adds a security-downgrade check** for authorised BSSIDs (cloned-BSSID evil twin). Channel changes alone are recorded but not alerted because access points legitimately auto-select channels. Hidden SSIDs are never matched.
5. **Rogue-AP severity is critical, ARP high, deauth high, device medium** (existing defaults).
6. **First run floods the device rule.** With an empty `observed_devices` table, every client of your access points raises one "unrecognised device" alert on first sight. Authorise the known devices first (the "authorise all observed" action exists for this), or start from a database where the observed list is already filled. A learning period is not built.

## Authorising your access points

The engine only trusts access points you have authorised. Until at least one is, the unrecognised-device rule is silent and
every access point advertising your network name looks like a rogue. Ways to authorise (all do the same thing):

```bash
flask --app wifiguard list-aps                                   # what is known, and what is authorised
flask --app wifiguard authorise-ap --ssid Campus-WiFi --bssid 28:6C:07:4A:11:F4 --channel 6 --security WPA3 --location "Admin block"
flask --app wifiguard authorise-observed                         # first-time setup: adopt what the engine has heard
flask --app wifiguard remove-ap 28:6C:07:4A:11:F4
```

`authorise-observed` (and the API `POST /api/access-points/authorise-all`) covers the **institutional network name from
Settings only**, never neighbouring networks, unless you name other SSIDs or BSSIDs. It shows what it will do and asks first.
It is *trust on first use*: during first-time setup it trusts whatever is on air at that moment, so check the list against your
own equipment. Once any access point is authorised, a lookalike with your network name is skipped as a suspected rogue; add it
deliberately with `authorise-ap` or `--bssid` if it is genuinely yours.

Authorising an access point does not close alerts already raised for it; resolve those on the Alerts screen.
The running engine reloads the authorised lists every 10 seconds, so changes need no restart.

## Replay mode (portable engine)

`python run.py --demo` loads the demo dataset if the database is empty, creates the administrator on first run, and starts the
engine replaying the `baseline` scenario in a loop. The Dashboard then shows the engine running, a live packet rate, the frame
mix and the Network Monitor feed, and the capture sources read `replay: baseline` and `replay: ARP`.

How it behaves:

- **Time is rebased to now.** Each scenario starts at the moment it is played and its frames are stamped with the moment they
  are released, so loops and layered scenarios never run time backwards and the rules, cool-downs and alert times behave as
  they would live. The recorded times are only used for spacing. Long silences in a recording are shortened to 2 seconds.
- **Scenarios layer on top of the baseline.** Triggering an attack mixes its frames into the normal traffic, in time order.
- **Same code path as live.** Frames go through `Processor`, `DetectionEngine` and `Pipeline` exactly as captured ones would.
  Only the frame source differs.

Controlling it (all need a signed-in session and the `X-WifiGuard-Client: 1` header; see `api.md`):

| Call | Effect |
| --- | --- |
| `GET /api/engine` | state, counters, scenarios available, setup warnings |
| `POST /api/engine/start` `{background?, loop?, speed?}` | start. `background` is a scenario id or `null` (silence until triggered), default `baseline` |
| `POST /api/engine/trigger` `{scenario}` | play a scenario now: `deauth`, `arp_conflict`, `rogue_ap`, `unknown_device` |
| `POST /api/engine/stop` | stop; the dashboard shows the engine as stopped |

`speed` scales time (2 = twice as fast, which also doubles frame rates, so rate-based rules see a higher rate). With
`loop: false` the background plays once, then the engine waits for triggers.

Your own recordings: put a `.pcap` or `.pcapng` in `samples/pcaps/` (or set `WIFIGUARD_REPLAY_DIR`); it appears in the scenario
list. A scenario with ARP traffic uses a second file named `<name>-arp.pcap`.

Things to know when demonstrating:

- **Run the demo dataset the scenarios were written for.** They use the access points, devices and addresses in `seed_demo.py`.
  Against other data the baseline is not quiet (every client is new) and the rogue and device scenarios may not match.
- **Repeats are merged, not duplicated.** Triggering a scenario again inside its cool-down (60 s deauth and ARP, 300 s rogue AP)
  adds to the open alert's occurrence count instead of raising a new one. The unrecognised-device scenario fires only once per
  database, because the device is "observed" afterwards. To start over: `flask --app wifiguard seed-demo --reset`.
- **One process.** The engine thread lives in the web server process. Do not run several workers.
- **These are fabricated frames.** Replay proves the rules do what they claim on known input and makes demos repeatable. It does
  not show that capture works on real hardware or keeps up with a busy network; label it as replay in the report.

## Try it without the server

```bash
python tools/make_sample_pcaps.py                     # writes samples/pcaps/*.pcap (fabricated frames)
flask --app wifiguard seed-demo --reset
flask --app wifiguard replay-pcap samples/pcaps/baseline.pcap      # expect: New alerts: 0
flask --app wifiguard replay-pcap samples/pcaps/deauth.pcap        # expect: 1 deauth_flood
```

802.11 and ARP use different link types, so a scenario with both is written as `x.pcap` and `x-arp.pcap`.
Replay stamps alerts with the current time; add `--capture-times` to keep the times stored in the file.
Real captures can be replayed the same way (pcap or pcapng; RadioTap link type for Wi-Fi).

## Performance (measured on the build machine, not on your hardware)

Parsing plus all four rules ran at about 16,000 frames per second. Scapy's own dissection ran at about 2,300 per second and
is the bottleneck, so Phase 3 should capture with `store=False`, a BPF filter and drop-and-count under load. Phase 3 must measure this on the real adapter and host.
