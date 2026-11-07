import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session

from .crypto import load_keys
from .runtime import ROLES
from .transport import ProtocolError, Transport


def create_observer(root, registry):
    project = Path(__file__).resolve().parents[1]
    app = Flask(__name__, template_folder=str(project / "templates"), static_folder=str(project / "static"))
    secret_path = Path(root) / "observer" / "web_session.key"
    if not secret_path.exists():
        secret_path.write_bytes(secrets.token_bytes(32))
    app.secret_key = secret_path.read_bytes()
    app.config.update(MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    signing, encryption = load_keys(Path(root) / "observer")
    transport = Transport("observer", registry, signing, encryption)
    mutation_lock, probes = threading.Lock(), {}

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.before_request
    def authorize():
        if request.host.split(":", 1)[0] not in ("127.0.0.1", "localhost"):
            return jsonify({"error": "LOCALHOST_ONLY"}), 403
        if request.path.startswith("/api/"):
            if not session.get("observer"):
                return jsonify({"error": "OBSERVER_SESSION_REQUIRED"}), 401
            if request.method == "POST":
                if request.headers.get("X-Demo-CSRF") != session.get("csrf"):
                    return jsonify({"error": "CSRF_CHECK_FAILED"}), 403
                if request.headers.get("Origin") and request.headers["Origin"] != request.host_url.rstrip("/"):
                    return jsonify({"error": "CROSS_ORIGIN_REQUEST_BLOCKED"}), 403

    @app.get("/")
    def index():
        session["observer"] = True
        session.setdefault("csrf", secrets.token_urlsafe(24))
        return render_template("index.html", csrf=session["csrf"])

    @app.get("/api/state")
    def state():
        def fetch(role):
            try:
                return role, {"online": True, **transport.call(role, "state")}
            except ProtocolError:
                return role, {"online": False, "role": role}
        with ThreadPoolExecutor(max_workers=len(ROLES)) as pool:
            roles = dict(pool.map(fetch, ROLES))
        return jsonify({"roles": roles, "probes": probes, "synthetic": True, "version": "0.1.0"})

    @app.post("/api/actions/<action>")
    def action_endpoint(action):
        data = request.get_json(silent=True) or {}
        try:
            with mutation_lock:
                if action == "enroll":
                    result = transport.call("wallet", "enroll", data)
                elif action == "bet":
                    result = transport.call("wallet", "bet", data)
                elif action == "settle":
                    if data.get("bookmaker") not in ("bookmaker_alpha", "bookmaker_beta"):
                        raise ProtocolError("INVALID_BOOKMAKER")
                    result = transport.call(data["bookmaker"], "settle", data)
                elif action == "probe":
                    result = transport.call("cupis", "probe", data)
                    probes[data["client_id"]] = result
                elif action == "request":
                    result = transport.call("cupis", "create_request", data)
                elif action == "approve":
                    result = transport.call("wallet", "approve", data)
                elif action == "arbiter":
                    result = transport.call("arbiter", "decision", data)
                elif action == "resume":
                    result = transport.call("disclosure", "resume", data)
                elif action == "eligibility":
                    result = transport.call("cupis", "eligibility", data)
                elif action == "reset":
                    if data.get("confirmation") != "RESET_SYNTHETIC_DEMO":
                        raise ProtocolError("RESET_CONFIRMATION_REQUIRED")
                    for role in ROLES:
                        transport.call(role, "reset")
                    probes.clear()
                    result = {"reset": True}
                else:
                    raise ProtocolError("UNKNOWN_ACTION", 404)
            return jsonify(result)
        except ProtocolError as exc:
            return jsonify({"error": exc.code}), exc.status
        except (ValueError, KeyError, TypeError):
            return jsonify({"error": "INVALID_INPUT"}), 400

    return app
