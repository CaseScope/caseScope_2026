"""Shared HTTP error helpers for API routes."""

from flask import jsonify, request
from werkzeug.exceptions import Forbidden


def forbidden_error_response(error):
    """Return the canonical JSON 403 shape for API requests."""
    if request.path.startswith("/api/"):
        description = getattr(error, "description", "") or ""
        if not description or description == Forbidden.description:
            description = "Access denied"
        return jsonify({"success": False, "error": description}), 403
    return error
