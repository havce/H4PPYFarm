#!/usr/bin/env python3

import json
from requests.exceptions import JSONDecodeError
from flask import Flask, request, abort, session, redirect, send_from_directory
from config import cfg
from flags import flag_store, flag_submitter
from utils import error

app = Flask(__name__)
app.secret_key = cfg.secret_key


def verify_session() -> bool:
    return session.get("user") == request.remote_addr


@app.route("/", methods=["GET"])
def index():
    if verify_session():
        return send_from_directory("static", "html/index.html")
    return redirect("/auth")


@app.route("/auth", methods=["GET"])
def auth():
    if verify_session():
        return redirect("/")
    return send_from_directory("static", "html/auth.html")


@app.route("/api/auth", methods=["POST"])
def auth_api():
    if request.is_json and request.json["password"] == cfg.password:
        session["user"] = request.remote_addr
    else:
        abort(403)
    return ""


@app.route("/api/flags/<exp>", methods=["POST", "PUT"])
def flags_put(exp: str = None):
    if not verify_session():
        abort(403)

    if not (exp and isinstance(exp, str) and request.is_json):
        abort(400)
    try:
        flag_submitter.queue(exp, request.json)
    except JSONDecodeError:
        abort(400)
    return ""


@app.route("/api/flags", methods=["GET"])
def flags_get():
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


@app.route("/api/config", methods=["GET"])
def config():
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


if __name__ == "__main__":
    flag_store.start()
    flag_submitter.start()
    app.run(port=cfg.port)
    flag_submitter.join()
    flag_store.join()
