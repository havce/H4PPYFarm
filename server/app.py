#!/usr/bin/env python3

import json
import signal
import os

from flask import Flask, request, abort, session, redirect, send_from_directory, send_file, Response
from config import cfg
from db import db
from flags import flag_store, flag_submitter
from hfi import HfiManager
from utils import error, info
from waitress import create_server

app = Flask(__name__)
app.secret_key = cfg.secret_key


def verify_session() -> bool:
    return session.get("user") == request.remote_addr


@app.get("/")
def index() -> Response:
    if verify_session():
        return send_from_directory("static", "html/index.html")
    return redirect("/auth")


@app.get("/auth")
def auth() -> Response:
    if verify_session():
        return redirect("/")
    return send_from_directory("static", "html/auth.html")


@app.get("/script")
def script() -> Response:
    if verify_session():
        return send_from_directory("static", "files/start_sploit.py", as_attachment=True)
    return redirect("/auth")


@app.get("/hfi/<string:req_os>/<string:req_arch>")
def hfi_get(req_os: str, req_arch: str) -> Response:
    # in the user we don't trust
    req_os = os.path.basename(req_os)
    req_arch = os.path.basename(req_arch)
    path = HfiManager.get(req_os, req_arch)
    if path:
        return send_file(path, as_attachment=True)
    abort(404)


@app.get("/hfi/<string:req_os>/<string:req_arch>/timestamp")
def hfi_timestamp(req_os: str, req_arch: str) -> str:
    # in the user we don't trust pt. 2
    req_os = os.path.basename(req_os)
    req_arch = os.path.basename(req_arch)
    timestamp = HfiManager.timestamp(req_os, req_arch)
    if timestamp:
        return f'{{"timestamp": {timestamp}}}'
    abort(500)


@app.post("/api/auth")
def auth_api() -> str:
    if request.is_json and request.json["password"] == cfg.password:
        session["user"] = request.remote_addr
    else:
        abort(403)
    return "OK"


@app.route("/api/flags/<string:exp>", methods=["POST", "PUT"])
def flags_put(exp: str = None) -> str:
    if not verify_session():
        abort(403)

    if not (exp and isinstance(exp, str) and request.is_json):
        abort(400)
    try:
        flag_submitter.queue(exp, request.json)
    except json.JSONDecodeError:
        abort(400)
    return "OK"


@app.get("/api/flags")
def flags_get() -> str:
    if not verify_session():
        abort(403)

    try:
        start = int(request.args.get("start", 0))
        count = int(request.args.get("count", 10))
        sliced = flag_store.slice(start, count)
        return json.dumps(sliced)
    except ValueError:
        abort(400)
    except Exception as exc:
        error(f"An error occurred while converting flags array to json")
        error(exc)
        abort(500)


@app.get("/api/config")
def config() -> str:
    if not verify_session():
        abort(403)

    try:
        return json.dumps({
            "flag_format": cfg.flag_format,
            "flag_lifetime": cfg.flag_lifetime,
            "tick_duration": cfg.tick_duration,
            "teams": cfg.teams
        })
    except Exception as exc:
        error(f"An error occurred while converting the configuration to json")
        error(exc)
        abort(500)


@app.route("/api/hfi", methods=["GET", "POST"])
def hfi() -> str:
    if not verify_session():
        abort(403)

    if request.method == "POST":
        if not request.is_json:
            abort(400)
        try:
            json_data = request.json
            if isinstance(json_data, dict):
                if json_data.get("remove", False):
                    HfiManager.remove_checker(json_data)
                else:
                    HfiManager.add_checker(json_data)
            else:
                abort(400)
        except Exception as exc:
            error("An error occurred while adding checkers")
            error(exc)
            abort(500)

    try:
        return json.dumps(HfiManager.get_checkers())
    except Exception as exc:
        error("An error occurred while converting data for HFI to json")
        error(exc)
        abort(500)



if __name__ == "__main__":
    db.start()
    HfiManager.create_table()
    flag_store.start()
    flag_submitter.start()

    if os.getenv("FARM_DEBUG"):
        app.run(host=cfg.address, port=cfg.port)
    else:
        server = create_server(app, host=cfg.address, port=cfg.port)

        def stop(sig, _frame):
            if sig == signal.SIGINT or sig == signal.SIGTERM:
                info("Stopping server...")
                server.close()
                flag_submitter.join()
                flag_store.join()
                db.join()

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        server.run()
