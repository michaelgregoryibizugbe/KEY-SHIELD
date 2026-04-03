"""
KeyShield Web GUI v3.0
BUG FIXES: thread lock, path traversal prevention, history cap, SSE.
"""

import os
import json
import hashlib
import threading
from datetime import datetime

from flask import (
    Flask, render_template, jsonify, request,
    send_from_directory, Response, stream_with_context,
)

from ..core.engine import ScanEngine, ScanResult
from ..utils.reporter import ReportGenerator, REPORTS_DIR
from ..utils.system_info import get_system_info
from ..utils.helpers import is_admin, secure_filename


MAX_HISTORY = 50

# Thread-safe scan state
_lock = threading.Lock()
_scan_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "current_detector": "",
    "result": None,
    "error": None,
}
_scan_history = []


def create_app() -> Flask:
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    # Deterministic secret from hostname (BUG FIX: survives restart)
    import platform
    app.secret_key = hashlib.sha256(
        f"keyshield-{platform.node()}".encode()
    ).digest()

    # ── Pages ────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            system_info=get_system_info(),
            is_admin=is_admin(),
            scan_history=_scan_history[-10:],
        )

    @app.route("/scan")
    def scan_page():
        return render_template("scan.html")

    @app.route("/report/<scan_id>")
    def report_page(scan_id):
        result_data = None
        with _lock:
            for entry in _scan_history:
                if entry.get("scan_id") == scan_id:
                    result_data = entry
                    break
        return render_template("report.html", result=result_data)

    @app.route("/history")
    def history_page():
        with _lock:
            history = list(reversed(_scan_history))
        return render_template("history.html", history=history)

    @app.route("/settings")
    def settings_page():
        return render_template(
            "settings.html",
            system_info=get_system_info(),
            is_admin=is_admin(),
        )

    # ── API ──────────────────────────────────────────

    @app.route("/api/scan/start", methods=["POST"])
    def api_start_scan():
        with _lock:
            if _scan_state["running"]:
                return jsonify({"error": "Scan already in progress"}), 409

        data = request.get_json(silent=True) or {}
        quick = data.get("quick", False)
        profile = data.get("profile") # Use config default if None

        def run_scan():
            with _lock:
                _scan_state["running"] = True
                _scan_state["progress"] = 0
                _scan_state["error"] = None
                _scan_state["result"] = None

            def progress_cb(name, current, total):
                with _lock:
                    _scan_state["current_detector"] = name
                    _scan_state["progress"] = current
                    _scan_state["total"] = total

            try:
                engine = ScanEngine()
                result = engine.run_scan(quick=quick, profile=profile, progress_callback=progress_cb)
                result_dict = result.to_dict()

                with _lock:
                    _scan_state["result"] = result_dict
                    _scan_history.append(result_dict)
                    # Cap history (BUG FIX: memory leak)
                    while len(_scan_history) > MAX_HISTORY:
                        _scan_history.pop(0)

                try:
                    ReportGenerator.generate_json_report(result)
                    ReportGenerator.generate_text_report(result)
                    ReportGenerator.generate_csv_report(result)
                except Exception:
                    pass

            except Exception as e:
                with _lock:
                    _scan_state["error"] = str(e)
            finally:
                with _lock:
                    _scan_state["running"] = False

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        return jsonify({"status": "started", "quick": quick, "profile": profile})

    @app.route("/api/scan/status")
    def api_scan_status():
        with _lock:
            return jsonify({
                "running": _scan_state["running"],
                "progress": _scan_state["progress"],
                "total": _scan_state["total"],
                "current_detector": _scan_state["current_detector"],
                "has_result": _scan_state["result"] is not None,
                "error": _scan_state["error"],
            })

    @app.route("/api/scan/result")
    def api_scan_result():
        with _lock:
            if _scan_state["result"]:
                return jsonify(_scan_state["result"])
        return jsonify({"error": "No results"}), 404

    @app.route("/api/scan/stream")
    def api_scan_stream():
        """SSE endpoint for real-time scan progress."""
        def generate():
            import time
            while True:
                with _lock:
                    data = {
                        "running": _scan_state["running"],
                        "progress": _scan_state["progress"],
                        "total": _scan_state["total"],
                        "current_detector": _scan_state["current_detector"],
                        "has_result": _scan_state["result"] is not None,
                        "error": _scan_state["error"],
                    }

                yield f"data: {json.dumps(data)}\n\n"

                if not data["running"] and (data["has_result"] or data["error"]):
                    break

                time.sleep(0.4)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/api/system")
    def api_system_info():
        return jsonify({"system_info": get_system_info(), "is_admin": is_admin()})

    @app.route("/api/history")
    def api_history():
        with _lock:
            return jsonify({"history": list(reversed(_scan_history))})

    @app.route("/api/reports")
    def api_reports():
        reports = []
        if os.path.exists(REPORTS_DIR):
            for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
                if f.endswith((".json", ".txt", ".csv")):
                    fpath = os.path.join(REPORTS_DIR, f)
                    reports.append({
                        "filename": f,
                        "size": os.path.getsize(fpath),
                        "modified": datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat(),
                    })
        return jsonify({"reports": reports})

    @app.route("/api/config/whitelist", methods=["GET", "POST", "DELETE"])
    def api_whitelist():
        from ..core.config import get_config
        config = get_config()
        
        if request.method == "GET":
            return jsonify({"whitelist": sorted(list(config.whitelist))})
            
        data = request.get_json(silent=True) or {}
        process = data.get("process")
        
        if not process:
            return jsonify({"error": "No process name provided"}), 400
            
        if request.method == "POST":
            config.add_to_whitelist(process)
            return jsonify({"status": "added", "process": process})
            
        if request.method == "DELETE":
            config.remove_from_whitelist(process)
            return jsonify({"status": "removed", "process": process})

    @app.route("/api/config/profile", methods=["POST"])
    def api_set_profile():
        from ..core.config import get_config
        config = get_config()
        data = request.get_json(silent=True) or {}
        profile_name = data.get("profile")
        
        if profile_name in ["quick", "standard", "paranoid"]:
            config.set_profile(profile_name)
            return jsonify({"status": "updated", "profile": profile_name})
        return jsonify({"error": "Invalid profile name"}), 400

    @app.route("/api/reports/download/<filename>")
    def api_download_report(filename):
        # BUG FIX: path traversal prevention
        safe_name = secure_filename(filename)
        return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)

    return app
