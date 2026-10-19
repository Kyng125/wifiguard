-- WiFiGuard schema (SQLite). Timestamps are UTC ISO-8601 text with milliseconds.
-- Tables marked [report] are the seven tables of Chapter 3, Table 3.4 (with added columns).
-- Tables marked [added] support the dashboard and the evaluation and are new.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

-- [report] reference list of approved access points
CREATE TABLE IF NOT EXISTS authorised_access_points (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid          TEXT NOT NULL,
    bssid         TEXT NOT NULL UNIQUE,
    channel       INTEGER,
    security_mode TEXT,
    description   TEXT,              -- location label, e.g. "Library"
    created_at    TEXT NOT NULL
);

-- [report] reference list of approved client devices
CREATE TABLE IF NOT EXISTS authorised_devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL UNIQUE,
    owner_label TEXT,
    device_type TEXT,
    status      TEXT NOT NULL DEFAULT 'authorised',
    created_at  TEXT NOT NULL
);

-- [report] access points actually heard on the air
CREATE TABLE IF NOT EXISTS observed_access_points (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid            TEXT,
    bssid           TEXT NOT NULL UNIQUE,
    channel         INTEGER,
    signal_strength INTEGER,         -- dBm
    security_mode   TEXT,            -- [added]
    status_override TEXT CHECK (status_override IN ('neighbouring') OR status_override IS NULL), -- [added]
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

-- [report] client devices actually heard on the air
CREATE TABLE IF NOT EXISTS observed_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address     TEXT NOT NULL UNIQUE,
    associated_bssid TEXT,
    review_state    TEXT NOT NULL DEFAULT 'none' CHECK (review_state IN ('none', 'under_review')), -- [added]
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

-- [report] IP-to-MAC bindings learned from ARP
CREATE TABLE IF NOT EXISTS arp_bindings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    trusted     INTEGER NOT NULL DEFAULT 0,
    UNIQUE (ip_address, mac_address)
);

-- [report] every alert with its evidence
CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time  TEXT NOT NULL,       -- when the event was first detected
    category    TEXT NOT NULL CHECK (category IN ('deauth_flood','arp_conflict','rogue_ap','unauthorised_device')),
    severity    TEXT NOT NULL CHECK (severity IN ('critical','high','medium','info')),
    source      TEXT,
    target      TEXT,
    description TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '{}',   -- JSON object
    status      TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','investigating','resolved','false_positive')),
    -- [added] columns
    ssid        TEXT,
    bssid       TEXT,
    channel     INTEGER,
    rule        TEXT,
    occurrences INTEGER NOT NULL DEFAULT 1,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT,
    dedupe_key  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time   ON security_events (event_time);
CREATE INDEX IF NOT EXISTS idx_events_status ON security_events (status);
CREATE INDEX IF NOT EXISTS idx_events_dedupe ON security_events (dedupe_key, last_seen);
CREATE INDEX IF NOT EXISTS idx_events_bssid  ON security_events (bssid);

-- [added] timeline and notes for an alert (kind: detected, threshold, generated, merged, status, note)
CREATE TABLE IF NOT EXISTS event_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
    at       TEXT NOT NULL,
    kind     TEXT NOT NULL,
    text     TEXT NOT NULL,
    actor    TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_log_event ON event_log (event_id, at);

-- [added] administrator notes about a device
CREATE TABLE IF NOT EXISTS device_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    text        TEXT NOT NULL,
    author      TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_notes_mac ON device_notes (mac_address);

-- [report] thresholds, cool-downs and interface settings
CREATE TABLE IF NOT EXISTS system_settings (
    setting_name  TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- [added] the single administrator account (the dashboard is single-admin by design)
CREATE TABLE IF NOT EXISTS admin_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

-- [added] failed sign-ins, so a lockout survives a restart (Phase 5). Rows older than the lockout window are pruned.
-- `at` is Unix time in seconds (a monotonic clock would not survive a restart). `key` is "<ip>|<username>" or "<ip>".
CREATE TABLE IF NOT EXISTS login_failures (
    id  INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_failures_key ON login_failures (key, at);

-- [added] evaluation log: one row per trial of the five scenarios (Table 3.5, Appendix B)
CREATE TABLE IF NOT EXISTS test_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario       TEXT NOT NULL CHECK (scenario IN ('normal_baseline','deauth','arp_conflict','rogue_ap','unknown_device')),
    trial          INTEGER NOT NULL,
    event_start    TEXT NOT NULL,
    alert_event_id INTEGER REFERENCES security_events(id) ON DELETE SET NULL,
    alert_time     TEXT,
    detected       INTEGER NOT NULL DEFAULT 0,   -- baseline: 1 means a false alert was raised
    cpu_percent    REAL,
    memory_percent REAL,
    notes          TEXT,
    is_sample      INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);

-- [added] latest runtime state written by the capture/detection side (Phase 3), read by the API
CREATE TABLE IF NOT EXISTS monitor_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT NOT NULL,
    packets_total   INTEGER NOT NULL DEFAULT 0,
    packets_per_sec INTEGER NOT NULL DEFAULT 0,
    mgmt_count      INTEGER NOT NULL DEFAULT 0,
    data_count      INTEGER NOT NULL DEFAULT 0,
    arp_count       INTEGER NOT NULL DEFAULT 0,
    engine_state    TEXT NOT NULL DEFAULT 'unknown',   -- running | stopped
    monitor_state   TEXT NOT NULL DEFAULT 'unknown',   -- up | down
    arp_state       TEXT NOT NULL DEFAULT 'unknown',   -- up | down
    current_channel INTEGER,
    cpu_percent     REAL,
    memory_percent  REAL
);

-- [added] short rolling sample of frames for the Network Monitor feed (no payloads, ever)
CREATE TABLE IF NOT EXISTS frame_samples (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    at           TEXT NOT NULL,
    frame_type   TEXT NOT NULL CHECK (frame_type IN ('management','data','arp')),
    subtype      TEXT,
    source       TEXT,
    destination  TEXT,
    bssid        TEXT,
    channel      INTEGER,
    flag_event_id INTEGER
);
