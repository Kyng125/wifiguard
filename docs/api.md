# WiFiGuard API contract

All routes are under `/api`, return JSON, and (except `/api/ping` and `/api/auth/login`) need a signed-in session.
Same origin only. Every non-GET request must send `X-WifiGuard-Client: 1`.

## Conventions

- JSON field names are camelCase. Timestamps are UTC ISO-8601 (`2026-10-12T08:09:26.991Z`); convert for display.
- Errors: `{ "error": { "code", "message", "details"? } }`. Validation errors are 422 with `details.field`.
  401 means sign in again; 403 `csrf_header_missing`; 429 `too_many_attempts` (with `Retry-After`; the lockout is stored in the database and survives a restart, see docs/deployment.md).
- Lists: `?page=1&pageSize=25` (max 100) and return `{ items, total, page, pageSize }`.
- Alert ids look like `EV-1054` (`EV-` and four digits); the API also accepts the bare number.
- Enumerations: alert `status` = `new | investigating | resolved | false_positive`; `severity` = `critical | high | medium | info`;
  `category` = `deauth_flood | arp_conflict | rogue_ap | unauthorised_device`; device `status` = `authorised | unrecognised | under_review`;
  access point `status` = `authorised | suspected_rogue | neighbouring | offline`. The UI maps these to display labels.

## Endpoints

| Function (frontend) | Method and path | Notes |
| --- | --- | --- |
| signIn | POST `/auth/login` `{username, password}` | sets the session cookie; returns `{user}` |
| signOut | POST `/auth/logout` | |
| getSession | GET `/auth/session` | 401 when signed out |
| changePassword | POST `/auth/password` `{currentPassword, newPassword}` | min 8 characters |
| getHealth | GET `/health` | `{cpuPercent, memoryPercent, packetsPerSecond, detectionEngine, database, captureSources[], updatedAt}`; engine is `running`, `stopped` or `unknown` |
| getOverview | GET `/overview` | `{openAlerts{total,critical,high,medium,info,warnings}, devices{...summary}, accessPoints{...summary}, rules{enabled,total}, detectionEngine}` |
| getAlerts | GET `/alerts` | filters: `status` (comma list or `open`), `severity`, `category`, `q`, `from`, `to` (dates are in the configured time zone), `bssid`, `source` |
| getAlert | GET `/alerts/:id` | adds `timeline[]`, `notes[]`, `relatedIds[]` |
| updateAlertStatus | PATCH `/alerts/:id` `{status, note?}` | returns the detail |
| addAlertNote | POST `/alerts/:id/notes` `{text}` | returns the detail |
| getAlertStats | GET `/stats/alerts?range=1h\|6h\|24h\|7d` | `{buckets[{start,count}], bucketSeconds, byCategory, total}` |
| exportAlertsCsv | GET `/alerts/export.csv` | same filters; formulas neutralised |
| getDevices | GET `/devices` | filters `status` (also `offline`), `q`; response adds `summary{total,active,observed24h,authorised,unrecognised,underReview,discoveredLast24h}` |
| getDevice | GET `/devices/:mac` | adds `notes[]`, `events[]` |
| addAuthorisedDevice | POST `/devices/authorised` `{macAddress, ownerLabel?, deviceType?}` | 409 if already authorised |
| updateDeviceStatus | PATCH `/devices/:mac` `{status}` | `authorised`, `under_review` or `unrecognised`; 409 for an authorised device (remove it first) |
| removeAuthorisedDevice | DELETE `/devices/authorised/:mac` | |
| addDeviceNote | POST `/devices/:mac/notes` `{text}` | |
| authoriseAllObserved | POST `/devices/authorise-all` and `/access-points/authorise-all` | returns `{authorised}` (access points also `skipped`). **Access points:** optional body `{ssids?, bssids?}`; with none, covers the institutional SSID only, never neighbouring networks; once any AP is authorised, lookalikes of a known SSID are skipped (see `engine.md`) |
| getAccessPoints | GET `/access-points` | filters `status`, `q`; response `{items, summary{total,authorised,suspectedRogue,neighbouring,offline}}` (`authorised` includes offline ones) |
| getAccessPoint | GET `/access-points/:bssid` | adds `devices[]`, `events[]` |
| addAuthorisedAp | POST `/access-points/authorised` `{ssid, bssid, channel?, securityMode?, location?}` | |
| updateAccessPointStatus | PATCH `/access-points/:bssid` `{status}` | `authorised` or `neighbouring` |
| removeAuthorisedAp | DELETE `/access-points/authorised/:bssid` | |
| getTopology | GET `/topology` | `{network, accessPoints[], devices[]}` |
| getRules | GET `/rules` | `{items[{id,name,category,description,editable[],severity,enabled,threshold?,windowSeconds?,cooldownSeconds}]}` |
| saveRule | PUT `/rules/:id` `{enabled?, threshold?, windowSeconds?, cooldownSeconds?}` | only the fields listed in `editable` |
| getMonitorStatus | GET `/monitor/status` | sources, counters, frame mix, channels, channel mode; additive: `source{kind: replay\|none, ...}` and `warnings[]` |
| getMonitorFeed | GET `/monitor/feed?since=ID&limit=50` | `{items, lastId}`; poll with the last id |
| getTestRuns / addTestRun | GET, POST `/test-runs` | POST: `{scenario, eventStart, detected, alertTime?, alertEventId?, trial?, cpuPercent?, memoryPercent?, notes?}`; a linked `alertEventId` supplies the alert time |
| getTestResults | GET `/test-runs/summary` | per scenario and overall; `isSample` is true while only demo runs exist |
| getSettings / saveSettings | GET, PUT `/settings` | GET returns nested groups `general{systemName,institutionalSsid,timezone,refreshIntervalSeconds}`, `monitoring{monitorInterface,arpInterface,channelMode,channels,channelDwellMs}`, `security{sessionTimeoutMinutes}`, `data{retentionDays}`, and read-only `alerts{severityByCategory}`. PUT takes the same nested shape with only the keys to change (e.g. `{"general":{"refreshIntervalSeconds":10}}`); unknown or read-only keys return 422 with `details.field`. |

## Additions after contract v1 (backend v1.3)

All additive: the frontend can ignore them until a screen needs them.

- `GET /overview` and `GET /monitor/status` carry `warnings[]`: `{code, severity: "warning"|"info", message}`. Codes:
  `no_authorised_aps` (the device rule is inactive and every lookalike SSID looks rogue) and `no_device_baseline` (expect one
  alert per client on first sight). Show them as a banner on the Dashboard.
- `GET /monitor/status` carries `source`: `{kind: "none"}` or `{kind: "replay", background, triggered[], loop, speed}`. While
  replaying, `sources[].name` is `replay: <scenario>` and `sources[].mode` is `replay`. `mode` is a free string in `types.ts`.
- `POST /access-points/authorise-all` accepts `{ssids?, bssids?}` and returns `{authorised, skipped}`. Its meaning changed: it no
  longer authorises neighbouring networks (it used to, and it skipped the institution's own access points on first run).
- Engine control (replay mode): `GET /engine`, `POST /engine/start`, `POST /engine/stop`, `POST /engine/trigger`. See `engine.md`.
  Errors: 409 `engine_running` / `engine_not_running`, 422 for an unknown scenario or a bad `speed` (0.25 to 20), 503
  `replay_unavailable` if scapy is missing.

Copy `warnings` into `types.ts` (`Overview.warnings`, `MonitorStatus.warnings`, `MonitorStatus.source`) when the Dashboard banner is built.

## What the frontend must change (client.ts)

1. Send `X-WifiGuard-Client: 1` on every request and use `credentials: 'include'` (same origin).
2. In development proxy `/api` to Flask (for example `server.proxy` in `vite.config.ts`); in production Flask serves the built files.
3. Use the enumerations above (snake_case) and map them to display labels.
4. `getDevices` and `getAccessPoints` return a `summary`, so the metric cards need no extra call.
5. `ownerLabel` is only available for authorised devices. Under-review and unrecognised devices have none.
6. The Monitor and Settings screens should show the channel list and channel mode, not a single channel.
7. Rename the sample device "Staff-Phone-Ade" to "Staff-Phone-01" in the frontend mock data (personal labels, report Section 3.14).


## Contract v1 additions (frontend cross-check)

- `/overview` includes `network` (the institutional SSID, setting `general.institutionalSsid`, default `Campus-WiFi`). A beacon with this SSID from an unknown BSSID is the rogue-AP signal.
- `/health` includes `packetsPerSecondSeries` (13 values, oldest first; `[]` while the engine is not reporting).
- `/stats/alerts` includes `open{total, byCategory}`: current open alerts regardless of `range` (the dashboard donut).
- Evidence keys are required per category when an alert is created:
  `deauth_flood` → `frameCount, windowSeconds, threshold`; `arp_conflict` → `ip, previousMac, newMac`;
  `rogue_ap` → `ssid, channel, securityMode`; `unauthorised_device` → `associatedBssid`.
- Alert filters accept comma lists (`status=new,investigating`) and `status=open`.
- `tests/test_contract.py` pins the exact key sets of every response. The frontend's `src/api/types.ts` mirrors them.
