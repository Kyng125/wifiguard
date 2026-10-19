"""Engine control (added after contract v1; the frontend does not use these yet).

The engine runs in the background from a replay source. These endpoints start and stop it and trigger a scenario
on top of the normal activity, so a demo can show each detection on cue.
"""
from flask import request

from ..errors import ApiError
from ..services import engine_control, monitor
from ..validators import invalid, json_body
from . import bp

SPEED_RANGE = (0.25, 20.0)


def _state() -> dict:
    runtime = engine_control.get_runtime()
    return {**runtime.status(), "scenarios": runtime.scenarios(), "warnings": monitor.warnings()}


@bp.get("/engine")
def engine_status():
    return _state()


@bp.post("/engine/start")
def engine_start():
    """Body (all optional): {"background": "baseline" | null, "loop": true, "speed": 1}."""
    data = json_body() if request.get_data() else {}      # an empty POST means "use the defaults"
    background = data.get("background", "baseline")
    if background is not None and not isinstance(background, str):
        raise invalid("background", "background must be a scenario id or null.")
    loop = data.get("loop", True)
    if not isinstance(loop, bool):
        raise invalid("loop", "loop must be true or false.")
    speed = data.get("speed", 1)
    if isinstance(speed, bool) or not isinstance(speed, (int, float)) or not SPEED_RANGE[0] <= speed <= SPEED_RANGE[1]:
        raise invalid("speed", f"speed must be a number from {SPEED_RANGE[0]} to {SPEED_RANGE[1]:g}.")
    runtime = engine_control.get_runtime()
    try:
        runtime.start(background, loop, float(speed))
    except RuntimeError:
        raise ApiError(409, "engine_running", "The engine is already running. Stop it first.")
    except KeyError:
        raise invalid("background", "Unknown scenario.")
    except ImportError:
        raise ApiError(503, "replay_unavailable", "Packet replay needs the scapy package. Run: pip install scapy")
    return _state()


@bp.post("/engine/stop")
def engine_stop():
    engine_control.get_runtime().stop()
    return _state()


@bp.post("/engine/trigger")
def engine_trigger():
    """Body: {"scenario": "deauth"}. Plays that scenario now, layered on whatever is already playing."""
    scenario = json_body().get("scenario")
    if not isinstance(scenario, str):
        raise invalid("scenario", "scenario is required.")
    runtime = engine_control.get_runtime()
    try:
        runtime.trigger(scenario)
    except RuntimeError:
        raise ApiError(409, "engine_not_running", "Start the engine before triggering a scenario.")
    except KeyError:
        raise invalid("scenario", "Unknown scenario.")
    return _state()
