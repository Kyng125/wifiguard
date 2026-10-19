"""Access to the in-process replay runtime, created on first use so the API starts quickly and works without scapy."""
import threading

from flask import current_app

_lock = threading.Lock()


def get_runtime(app=None):
    app = app or current_app._get_current_object()
    with _lock:
        runtime = app.extensions.get("replay_runtime")
        if runtime is None:
            from ..engine.runtime import ReplayRuntime
            runtime = ReplayRuntime(app, app.config["REPLAY_DIR"])
            app.extensions["replay_runtime"] = runtime
        return runtime


def existing_runtime():
    """The runtime if it has been created, else None. Never creates one."""
    return current_app.extensions.get("replay_runtime")
