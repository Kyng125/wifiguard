"""JSON API blueprint. Every route is under /api and requires a signed-in administrator, except
/api/ping and /api/auth/login."""
from flask import Blueprint, request

from .. import security
from ..errors import ApiError

bp = Blueprint("api", __name__, url_prefix="/api")

PUBLIC_ENDPOINTS = {"api.ping", "api.login"}


@bp.before_request
def _guard():
    security.require_client_header()
    if request.endpoint not in PUBLIC_ENDPOINTS and request.endpoint != "api.not_found":
        security.require_login()


@bp.route("/ping")
def ping():
    return {"ok": True}


@bp.route("/<path:_rest>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], endpoint="not_found")
def not_found(_rest):
    raise ApiError(404, "not_found", "No such API endpoint.")


# Import route modules last so they attach to bp.
from . import access_points, alerts, auth, devices, engine, monitor, reports, rules, settings, system  # noqa: E402,F401
