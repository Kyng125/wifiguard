"""Command-line tools: flask --app wifiguard <command>"""
from pathlib import Path

import click
from flask import current_app

from . import config as cfgmod
from . import db, maintenance, security, tlscert
from .errors import ApiError
from .services import events, inventory
from .services import settings as st
from .validators import SCENARIOS, SECURITY_MODES, normalise_mac


def _mac(value: str, field: str) -> str:
    try:
        return normalise_mac(value, field)
    except ApiError as exc:
        raise click.ClickException(f"{field}: {exc.message}")


def register(app):
    @app.cli.command("init-db")
    def init_db_command():
        """Create tables and default settings (safe to run again)."""
        conn = db.connect(current_app.config["DATABASE"])
        db.init_db(conn)
        conn.close()
        click.echo(f"Database ready: {current_app.config['DATABASE']}")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @click.option("--reset", is_flag=True, help="Change the password of an existing administrator.")
    def create_admin_command(username, password, reset):
        """Create the administrator account (or reset its password)."""
        if len(password) < current_app.config["MIN_PASSWORD_LENGTH"]:
            raise click.ClickException(f"Password must be at least {current_app.config['MIN_PASSWORD_LENGTH']} characters.")
        conn = db.connect(current_app.config["DATABASE"])
        try:
            security.create_admin(conn, username, password, reset=reset)
        except ValueError as exc:
            raise click.ClickException(str(exc))
        finally:
            conn.close()
        click.echo(f"Administrator '{username}' saved.")

    @app.cli.command("seed-demo")
    @click.option("--reset", is_flag=True, help="Delete existing data first (the admin account and settings are kept).")
    def seed_demo_command(reset):
        """Load the demo dataset so the dashboard can be explored without capture hardware."""
        from .seed_demo import seed
        try:
            counts = seed(reset=reset)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))
        click.echo("Demo data loaded: " + ", ".join(f"{k}={v}" for k, v in counts.items()))

    @app.cli.command("purge")
    def purge_command():
        """Delete closed alerts and runtime samples older than the retention period."""
        result = events.purge(st.get_int("retention_days"))
        click.echo(f"Purged: {result}")

    @app.cli.command("replay-pcap")
    @click.argument("pcap", type=click.Path(exists=True, dir_okay=False))
    @click.option("--capture-times", is_flag=True, help="Stamp alerts with the times inside the file instead of now.")
    def replay_pcap_command(pcap, capture_times):
        """Run a pcap/pcapng file through the detection engine (no adapter needed)."""
        from .engine.pipeline import Pipeline, replay
        pipeline = Pipeline(stamp="capture" if capture_times else "now", refresh_seconds=None)
        summary = replay(pcap, pipeline)
        click.echo(f"Frames analysed: {summary['frames']} (ignored {summary['ignored']}, malformed {summary['dropped']})")
        for display_id, category, source in summary["alerts"]:
            click.echo(f"  {display_id}  {category:<20} {source}")
        click.echo(f"New alerts: {len(summary['alerts'])}; repeats merged into existing alerts: {summary['merged']}")

    # ------------------------------------------------------------ deployment and maintenance (Phase 5)

    @app.cli.command("check-config")
    def check_config_command():
        """Show how the server is configured for transport security and list anything unsafe about it."""
        cfg = current_app.config
        tls = cfgmod.tls_enabled(cfg)
        click.echo(f"Address:            {cfg['HOST']}:{cfg['PORT']}")
        click.echo(f"TLS:                {'on (' + cfg['TLS_CERT'] + ')' if tls else 'off'}")
        click.echo(f"Secure cookie:      {'yes' if cfg['SESSION_COOKIE_SECURE'] else 'no'}")
        click.echo(f"Trusted proxies:    {cfg['TRUST_PROXY'] or 'none'}")
        click.echo(f"HSTS:               {str(cfg['HSTS_SECONDS']) + ' s' if cfg['HSTS_SECONDS'] else 'off'}")
        click.echo(f"Secret key from:    {cfgmod.secret_key_source()}")
        click.echo(f"Login lockout:      {cfg['LOGIN_MAX_FAILURES']} failures per address and name "
                   f"({cfg['LOGIN_MAX_FAILURES_PER_ADDRESS']} per address) for {cfg['LOGIN_LOCKOUT_SECONDS']} s")
        try:
            cfgmod.check_tls_files(cfg)
        except cfgmod.ConfigError as exc:
            click.echo(f"\nProblem: {exc}")
        warnings = cfgmod.deployment_warnings(cfg)
        for warning in warnings:
            click.echo(f"\nWarning: {warning}")
        if not warnings:
            click.echo("\nNo problems found with the transport settings.")

    @app.cli.command("unlock-login")
    def unlock_login_command():
        """Clear every login lockout (lockouts now survive restarts, so this is how to let yourself back in early)."""
        conn = db.connect(current_app.config["DATABASE"])
        try:
            cleared = security.clear_all_failures(conn)
        finally:
            conn.close()
        click.echo(f"Cleared {cleared} recorded failed sign-in(s).")

    @app.cli.command("rotate-secret-key")
    @click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
    def rotate_secret_key_command(yes):
        """Replace the session-signing key. Everyone, including you, is signed out; restart the server afterwards."""
        if not yes:
            click.confirm("This signs everyone out and takes effect when the server restarts. Continue?", abort=True)
        try:
            cfgmod.rotate_secret_key(Path(current_app.config["INSTANCE_DIR"]))
        except cfgmod.ConfigError as exc:
            raise click.ClickException(str(exc))
        click.echo("New secret key written to instance/secret_key. Restart the server to use it.")

    @app.cli.command("make-cert")
    @click.option("--host", "hosts", multiple=True, help="Name or IP address people will type to reach the server. Repeatable. "
                  "localhost and 127.0.0.1 are always included.")
    @click.option("--out", "out_dir", type=click.Path(file_okay=False), help="Folder for the files (default: instance/tls).")
    @click.option("--force", is_flag=True, help="Replace an existing certificate and key.")
    def make_cert_command(hosts, out_dir, force):
        """Create a self-signed certificate for a lab server (browsers will warn; see docs/deployment.md)."""
        folder = out_dir or str(Path(current_app.config["INSTANCE_DIR"]) / "tls")
        try:
            made = tlscert.make_self_signed(folder, list(hosts), force)
        except cfgmod.ConfigError as exc:
            raise click.ClickException(str(exc))
        click.echo(f"Certificate: {made['cert']}\nPrivate key: {made['key']}  (keep it secret; it is never needed by the browser)")
        click.echo(f"Valid until {made['expires']}. Covers: {', '.join(made['names'])}")
        click.echo(f"SHA-256 fingerprint: {made['fingerprint']}\n"
                   "On the first visit the browser will warn that the certificate is not trusted. Compare its fingerprint with the one above.")
        click.echo("\nStart with:  python run.py --production --cert {} --key {}".format(made["cert"], made["key"]))

    @app.cli.command("backup")
    @click.option("--out", help="A .zip file name, or a folder (default: instance/backups).")
    @click.option("--keep", type=click.IntRange(1, 1000), help="Afterwards delete the oldest backups in that folder beyond this many.")
    def backup_command(out, keep):
        """Back up the database (safe while the server runs). The secret key is not included."""
        try:
            made = maintenance.backup(current_app.config["DATABASE"], current_app.config["INSTANCE_DIR"], out, keep)
        except maintenance.MaintenanceError as exc:
            raise click.ClickException(str(exc))
        counts = made["manifest"]["counts"]
        click.echo(f"Backup written: {made['path']} ({made['bytes'] // 1024} KB)")
        click.echo(f"Contains: {counts.get('security_events', 0)} alerts, {counts.get('observed_devices', 0)} devices, "
                   f"{counts.get('observed_access_points', 0)} access points, {counts.get('test_runs', 0)} test runs, "
                   f"{len(made['manifest']['evaluationRuns'])} saved evaluation run(s).")
        for name in made["removed"]:
            click.echo(f"Removed old backup {name}")
        click.echo("It holds the administrator's password hash and your network's MAC addresses: store it somewhere private.")

    @app.cli.command("restore")
    @click.argument("archive", type=click.Path(exists=True, dir_okay=False))
    @click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
    @click.option("--force", is_flag=True, help="Restore even though a running server was detected.")
    def restore_command(archive, yes, force):
        """Replace the database with one from a backup. Stop the server first; the current data is saved first."""
        try:
            manifest = maintenance.read_manifest(archive)
            counts = manifest.get("counts", {})
            click.echo(f"Backup from {manifest.get('createdAt')} (WiFiGuard {manifest.get('appVersion')}): "
                       f"{counts.get('security_events', 0)} alerts, {counts.get('observed_devices', 0)} devices, "
                       f"{counts.get('test_runs', 0)} test runs.")
            if not yes:
                click.confirm("Replace the current database with it? The current one is backed up first.", abort=True)
            done = maintenance.restore(current_app.config["DATABASE"], current_app.config["INSTANCE_DIR"], archive, force)
        except maintenance.MaintenanceError as exc:
            raise click.ClickException(str(exc))
        if done["safetyBackup"]:
            click.echo(f"The previous database was saved as {done['safetyBackup']}")
        click.echo("Restored. Everyone must sign in again if the secret key changed. Start the server.")

    # ------------------------------------------------------------ authorised access points

    @app.cli.command("list-aps")
    def list_aps_command():
        """Show every access point WiFiGuard knows about and whether it is authorised."""
        items = inventory.filter_access_points(inventory.all_access_points(), None, None)
        if not items:
            click.echo("No access points yet. Add one with authorise-ap, or let the engine observe some first.")
            return
        click.echo(f"{'STATUS':<16}{'SSID':<24}{'BSSID':<19}{'CH':<5}{'SECURITY':<11}LAST SEEN")
        for ap in items:
            click.echo(f"{ap['status']:<16}{(ap['ssid'] or '(hidden)')[:23]:<24}{ap['bssid']:<19}"
                       f"{str(ap['channel'] or '-'):<5}{(ap['securityMode'] or '-'):<11}{ap['lastSeen'] or 'never'}")
        summary = inventory.access_points_summary(items)
        click.echo(f"\n{summary['authorised']} authorised, {summary['suspectedRogue']} suspected rogue, "
                   f"{summary['neighbouring']} neighbouring, {summary['offline']} offline.")
        if not summary["authorised"]:
            click.echo("\nNo access point is authorised yet, so the unrecognised-device rule stays silent. "
                       "Run: flask --app wifiguard authorise-ap --help")

    @app.cli.command("authorise-ap")
    @click.option("--ssid", required=True, help="Network name, e.g. Campus-WiFi.")
    @click.option("--bssid", required=True, help="The access point's MAC address, e.g. 28:6C:07:4A:11:F4.")
    @click.option("--channel", type=click.IntRange(1, 177), help="Channel it should use (optional).")
    @click.option("--security", type=click.Choice(SECURITY_MODES), help="Security mode it should use (optional but recommended).")
    @click.option("--location", help="Where it is installed, e.g. 'Admin block, 1st floor' (optional).")
    def authorise_ap_command(ssid, bssid, channel, security, location):
        """Add one access point you own to the authorised list."""
        try:
            ap = inventory.authorise_access_point(ssid, _mac(bssid, "bssid"), channel, security, location)
        except ApiError as exc:
            raise click.ClickException(exc.message)
        click.echo(f"Authorised {ap['ssid']} ({ap['bssid']}).")

    @app.cli.command("authorise-observed")
    @click.option("--ssid", "ssids", multiple=True, help="Authorise observed access points with this network name. Repeatable.")
    @click.option("--bssid", "bssids", multiple=True, help="Authorise this specific access point. Repeatable.")
    @click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
    def authorise_observed_command(ssids, bssids, yes):
        """Authorise access points the engine has already observed (first-time setup).

        With no options it covers the institutional network name from Settings only, never neighbouring networks.
        """
        try:
            plan = inventory.plan_bulk_authorisation(list(ssids), [_mac(b, "bssid") for b in bssids])
        except ApiError as exc:
            raise click.ClickException(exc.message)
        for bssid in plan["unknownBssids"]:
            click.echo(f"Note: {bssid} has not been observed, so it was ignored. Use authorise-ap to add it by hand.")
        for ap in plan["skipped"]:
            click.echo(f"Skipped {ap['ssid']} {ap['bssid']}: {ap['skipReason']}")
        if not plan["chosen"]:
            click.echo("Nothing to authorise.")
            return
        click.echo("Will authorise:")
        for ap in plan["chosen"]:
            click.echo(f"  {ap['ssid'] or '(hidden)':<24}{ap['bssid']}  ch {ap['channel'] or '-'}  {ap['securityMode'] or '-'}")
        if plan["firstTime"]:
            click.echo("\nThis is first-time setup, so WiFiGuard trusts everything listed above. If an access point "
                       "you do not own is advertising your network name right now, it would be trusted too. "
                       "Check the list against your own equipment.")
        if not yes:
            click.confirm("Authorise these access points?", abort=True)
        click.echo(f"Authorised {inventory.authorise_planned(plan['chosen'])} access point(s).")

    @app.cli.command("remove-ap")
    @click.argument("bssid")
    def remove_ap_command(bssid):
        """Remove an access point from the authorised list."""
        try:
            inventory.remove_authorised_access_point(_mac(bssid, "bssid"))
        except ApiError as exc:
            raise click.ClickException(exc.message)
        click.echo("Removed.")

    @app.cli.command("engine-status")
    def engine_status_command():
        """Show what the engine is doing, as the dashboard sees it, plus any setup warnings."""
        from .services import monitor
        status = monitor.status()
        click.echo(f"Engine: {status['detectionEngine']}   packets analysed: {status['packetsCaptured']}   "
                   f"rate: {status['packetsPerSecond']}/s")
        if status["source"]["kind"] == "replay":
            for source in status["sources"]:
                click.echo(f"  {source['role']:<8}{source['name']:<28}{source['mode']:<10}{source['state']}")
        elif status["detectionEngine"] == "running":
            click.echo("  (the engine is running inside the server; its source is shown on the dashboard)")
        for warning in status["warnings"]:
            click.echo(f"\n[{warning['severity']}] {warning['message']}")
        if status["detectionEngine"] != "running":
            click.echo("\nThe engine runs inside the web server process. Start it with: python run.py --demo")

    # --------------------------------------------------------------------------- evaluation (Chapter 4)

    @app.cli.group("evaluate")
    def evaluate_group():
        """Repeated simulated trials of the five scenarios, with the Section 3.13 measures (docs/evaluation.md)."""

    def _table(summary):
        click.echo(f"\n{'Scenario':<30}{'Trials':>7}{'Hits':>6}{'Rate %':>8}{'MTTD s':>8}{'CPU %':>7}{'Mem %':>7}")
        from .services.reports import SCENARIO_NAMES

        def cell(v):
            return "-" if v is None else str(v)
        for s in summary["scenarios"]:
            label = SCENARIO_NAMES[s["scenario"]] + (" (FP)" if s["kind"] == "baseline" else "")
            click.echo(f"{label:<30}{s['trials']:>7}{s['detected']:>6}{cell(s['rate']):>8}{cell(s['meanTimeToDetectSeconds']):>8}"
                       f"{cell(s['avgCpuPercent']):>7}{cell(s['avgMemoryPercent']):>7}")
        o = summary["overall"]
        def pct(v):
            return "n/a" if v is None else f"{v}%"
        click.echo(f"\nDetection rate {pct(o['detectionRate'])}   false-positive rate {pct(o['falsePositiveRate'])}   "
                   f"mean time to detect {'n/a' if o['meanTimeToDetectSeconds'] is None else str(o['meanTimeToDetectSeconds']) + ' s'}"
                   f"   runs {o['totalRuns']}")

    @evaluate_group.command("run")
    @click.option("--trials", default=10, show_default=True, type=click.IntRange(1, 1000), help="Repetitions per scenario.")
    @click.option("--seed", "seed_value", default=1, show_default=True, help="Random seed; the same seed repeats the run exactly.")
    @click.option("--mode", type=click.Choice(["fast", "realtime"]), default="fast", show_default=True,
                  help="fast: virtual clock, seconds to run. realtime: wall clock (about 30 minutes for the full run of 10 trials), also records CPU and memory.")
    @click.option("--speed", default=1.0, show_default=True, type=float, help="Realtime only: time compression (changes frame rates).")
    @click.option("--scenario", "scenarios", multiple=True, type=click.Choice(list(SCENARIOS)),
                  help="Only these scenarios (repeatable). Default: all five.")
    @click.option("--save", is_flag=True, help="Write the results into the Reports test-run log. Without it nothing is stored.")
    @click.option("--replace", is_flag=True, help="With --save: also replace earlier real results (demo samples are always replaced).")
    def evaluate_run(trials, seed_value, mode, speed, scenarios, save, replace):
        """Run the trials against the current rule settings and print the measures."""
        from .evaluation import export, harness
        settings = export.settings_for_run()
        chosen = tuple(scenarios) or harness.SCENARIOS
        click.echo(f"Evaluating {len(chosen)} scenario(s) x {trials} trials, {mode} mode, seed {seed_value}. "
                   "These are simulated trials (see docs/evaluation.md).")

        def progress(r):
            mark = ("FALSE ALERT" if r.detected else "clean") if r.scenario == "normal_baseline" else (
                f"detected in {r.seconds_to_detect}s" if r.detected else "MISSED")
            click.echo(f"  {r.scenario:<16}{r.trial:>3}  {mark}")
        try:
            evaluation = harness.run_evaluation(settings, trials, seed_value, chosen, mode, speed, progress)
        except harness.EvaluationError as exc:
            raise click.ClickException(str(exc))
        _table(harness.summarise(evaluation.results))
        if not save:
            click.echo("\nNothing was stored. Add --save to write these results into the test-run log.")
            return
        try:
            saved = harness.save(evaluation, current_app.config["INSTANCE_DIR"], replace)
        except harness.EvaluationError as exc:
            raise click.ClickException(str(exc))
        click.echo(f"\nSaved {saved['saved']} runs to the test-run log (Reports screen). Run metadata: {saved['metadata']}")
        click.echo("Next: flask --app wifiguard evaluate export")

    @evaluate_group.command("sweep")
    @click.option("--seconds", default=8.0, show_default=True, type=float, help="Burst length for the frame-count table.")
    @click.option("--csv", "csv_file", type=click.Path(dir_okay=False), help="Also write both tables to this CSV file.")
    def evaluate_sweep(seconds, csv_file):
        """Show how the deauthentication rule behaves at and around its threshold (for threshold calibration)."""
        from .evaluation import export, harness
        result = harness.sweep_deauth(export.settings_for_run(), seconds=seconds)
        click.echo(f"Threshold {result['threshold']} frames in {result['windowSeconds']} s. Burst only, no other traffic.\n")
        click.echo(f"{'Frames':>7}{'Over (s)':>10}{'Frames/s':>10}{'Detected':>10}{'After (s)':>11}")
        for label, rows in (("Varying the number of frames:", result["counts"]), ("\nSame frame count, stretched out:", result["durations"])):
            click.echo(label)
            for r in rows:
                click.echo(f"{r['frames']:>7}{r['seconds']:>10}{r['framesPerSecond']:>10}{'yes' if r['detected'] else 'no':>10}"
                           f"{'-' if r['secondsToDetect'] is None else r['secondsToDetect']:>11}")
        if csv_file:
            import csv as csvmodule
            with open(csv_file, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csvmodule.writer(handle)
                writer.writerow(["Table", "Frames", "Seconds", "Frames per second", "Detected", "Seconds to detect"])
                for table, rows in (("count", result["counts"]), ("duration", result["durations"])):
                    for r in rows:
                        writer.writerow([table, r["frames"], r["seconds"], r["framesPerSecond"], int(r["detected"]),
                                         "" if r["secondsToDetect"] is None else r["secondsToDetect"]])
            click.echo(f"\nWritten to {csv_file}")

    @evaluate_group.command("export")
    @click.option("--out", "out_dir", type=click.Path(file_okay=False), help="Folder for the files (default: instance/evaluation/export).")
    @click.option("--meta", "meta_file", type=click.Path(exists=True, dir_okay=False), help="Run metadata file (default: the latest run).")
    def evaluate_export(out_dir, meta_file):
        """Write test_runs.csv (Appendix B), metrics.csv, metrics.md and methodology.md for the report."""
        from .evaluation import export
        folder = out_dir or str(Path(current_app.config["INSTANCE_DIR"]) / "evaluation" / "export")
        try:
            written = export.write_all(folder, current_app.config["INSTANCE_DIR"], meta_file)
        except ValueError as exc:
            raise click.ClickException(str(exc))
        for path, what in written["files"].items():
            click.echo(f"  {path}   {what}")
        for warning in written["warnings"]:
            click.echo(f"Check: {warning}")
