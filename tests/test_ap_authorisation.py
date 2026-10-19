"""Authorising access points: the bulk rule (API) and the command-line tools."""
import pytest

from wifiguard import db, timeutil

HEADER = {"X-WifiGuard-Client": "1"}

OURS_A = "28:6C:07:4A:11:E0"
OURS_B = "28:6C:07:4A:11:F4"
FAKE = "7C:10:C9:5E:3A:92"
NEIGHBOUR = "9A:4B:21:C7:0D:36"


def observe(app, *aps):
    """Insert observed access points directly: (ssid, bssid, channel, mode)."""
    with app.app_context():
        for ssid, bssid, channel, mode in aps:
            db.get_db().execute(
                "INSERT INTO observed_access_points (ssid, bssid, channel, signal_strength, security_mode, first_seen, last_seen) "
                "VALUES (?, ?, ?, -50, ?, ?, ?)", (ssid, bssid, channel, mode, timeutil.iso(), timeutil.iso()))
        db.get_db().commit()


@pytest.fixture
def first_run(app, api):
    """No authorised access points yet; three heard on air: two ours, one neighbour."""
    observe(app, ("Campus-WiFi", OURS_A, 1, "WPA3"), ("Campus-WiFi", OURS_B, 6, "WPA3"),
            ("TECNO-MiFi-2F81", NEIGHBOUR, 11, "WPA2"))
    return api


# ---------------------------------------------------------------- bulk authorise (API)

def test_first_time_setup_adopts_institutional_aps_but_not_neighbours(first_run):
    assert first_run.post("/api/access-points/authorise-all").get_json() == {"authorised": 2, "skipped": 0}
    by_bssid = {a["bssid"]: a for a in first_run.get("/api/access-points").get_json()["items"]}
    assert by_bssid[OURS_A]["authorised"] and by_bssid[OURS_B]["authorised"]
    assert not by_bssid[NEIGHBOUR]["authorised"] and by_bssid[NEIGHBOUR]["status"] == "neighbouring"
    # What was observed is copied across so the rogue rule can spot a security downgrade later.
    assert by_bssid[OURS_A]["securityMode"] == "WPA3" and by_bssid[OURS_A]["channel"] == 1


def test_first_time_setup_trusts_a_rogue_that_is_on_air_then(first_run, app):
    observe(app, ("Campus-WiFi", FAKE, 6, "WPA2"))
    assert first_run.post("/api/access-points/authorise-all").get_json()["authorised"] == 3   # documented trade-off


def test_bulk_authorise_is_a_no_op_for_new_lookalikes_once_set_up(first_run, app):
    first_run.post("/api/access-points/authorise-all")
    observe(app, ("Campus-WiFi", FAKE, 6, "WPA2"))
    assert first_run.post("/api/access-points/authorise-all").get_json() == {"authorised": 0, "skipped": 1}
    assert not {a["bssid"]: a for a in first_run.get("/api/access-points").get_json()["items"]}[FAKE]["authorised"]


def test_naming_a_bssid_is_a_deliberate_override(first_run, app):
    first_run.post("/api/access-points/authorise-all")
    observe(app, ("Campus-WiFi", FAKE, 6, "WPA2"))
    assert first_run.post("/api/access-points/authorise-all", {"bssids": [FAKE]}).get_json()["authorised"] == 1


def test_explicit_ssid_scope_can_include_your_own_second_network(first_run):
    assert first_run.post("/api/access-points/authorise-all",
                          {"ssids": ["TECNO-MiFi-2F81"]}).get_json() == {"authorised": 1, "skipped": 0}
    assert first_run.get(f"/api/access-points/{OURS_A}").get_json()["authorised"] is False


def test_an_ap_marked_neighbouring_is_not_swept_in(first_run):
    assert first_run.patch(f"/api/access-points/{OURS_B}", {"status": "neighbouring"}).status_code == 200
    assert first_run.post("/api/access-points/authorise-all").get_json() == {"authorised": 1, "skipped": 1}


def test_bulk_authorise_needs_a_scope(first_run, app):
    with app.app_context():
        db.get_db().execute("UPDATE system_settings SET setting_value = '' WHERE setting_name = 'institutional_ssid'")
        db.get_db().commit()
    r = first_run.post("/api/access-points/authorise-all")
    assert r.status_code == 422 and r.get_json()["error"]["details"]["field"] == "ssids"
    assert first_run.post("/api/access-points/authorise-all", {"ssids": "Campus-WiFi"}).status_code == 422
    assert first_run.post("/api/access-points/authorise-all", {"bssids": ["nope"]}).status_code == 422


# ----------------------------------------------------------------------- command line

@pytest.fixture
def cli(app):
    runner = app.test_cli_runner()
    return lambda *args, **kw: runner.invoke(args=list(args), **kw)


def test_list_aps_explains_the_empty_and_unauthorised_states(app, cli):
    assert "No access points yet" in cli("list-aps").output
    observe(app, ("Campus-WiFi", OURS_A, 1, "WPA3"))
    out = cli("list-aps").output
    assert OURS_A in out and "No access point is authorised yet" in out


def test_authorise_ap_and_remove_ap(app, cli):
    r = cli("authorise-ap", "--ssid", "Campus-WiFi", "--bssid", "28-6c-07-4a-11-e0", "--channel", "1",
            "--security", "WPA3", "--location", "Library")
    assert r.exit_code == 0 and "Authorised Campus-WiFi (28:6C:07:4A:11:E0)" in r.output
    assert "already authorised" in cli("authorise-ap", "--ssid", "X", "--bssid", OURS_A).output
    assert cli("authorise-ap", "--ssid", "X", "--bssid", "nonsense").exit_code != 0
    assert cli("authorise-ap", "--ssid", "X", "--bssid", OURS_B, "--security", "WPA9").exit_code != 0
    assert "authorised" in cli("list-aps").output
    assert cli("remove-ap", OURS_A).output.strip() == "Removed."
    assert "not on the authorised list" in cli("remove-ap", OURS_A).output


def test_authorise_observed_previews_asks_and_applies(app, cli):
    observe(app, ("Campus-WiFi", OURS_A, 1, "WPA3"), ("TECNO-MiFi-2F81", NEIGHBOUR, 11, "WPA2"))
    declined = cli("authorise-observed", input="n\n")
    assert declined.exit_code != 0 and OURS_A in declined.output and NEIGHBOUR not in declined.output.split("Will authorise:")[1]
    assert "first-time setup" in declined.output
    with app.app_context():
        assert db.scalar("SELECT COUNT(*) FROM authorised_access_points") == 0   # nothing changed
    done = cli("authorise-observed", "--yes")
    assert done.exit_code == 0 and "Authorised 1 access point(s)." in done.output
    assert "Nothing to authorise." in cli("authorise-observed", "--yes").output


def test_authorise_observed_reports_unobserved_bssids(app, cli):
    observe(app, ("Campus-WiFi", OURS_A, 1, "WPA3"))
    out = cli("authorise-observed", "--bssid", OURS_B, "--yes").output
    assert OURS_B in out and "has not been observed" in out and "Nothing to authorise." in out
