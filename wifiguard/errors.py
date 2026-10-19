"""One JSON error shape for the whole API: {"error": {"code", "message", "details"?}}."""
from flask import jsonify
from werkzeug.exceptions import HTTPException


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def error_response(status: int, code: str, message: str, details=None):
    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return jsonify(body), status


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):
        return error_response(exc.status, exc.code, exc.message, exc.details)

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        code = (exc.name or "error").lower().replace(" ", "_")
        return error_response(exc.code or 500, code, exc.description or exc.name)

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):
        app.logger.exception("Unhandled error")
        # Never leak internals to the client.
        return error_response(500, "internal_error", "An unexpected error occurred.")
