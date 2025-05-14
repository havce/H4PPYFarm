import session
import flags
import log

from typing import Callable
from flask import Flask
from flask import request
from flask import send_from_directory, redirect, abort, jsonify
from werkzeug import Response
from config import Config
from database import db


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{Config.database}"
app.secret_key = Config.secret_key

db.init_app(app)


def page(name: str) -> Response:
    return send_from_directory("static/html", f"{name}.html")


def file(name: str) -> Response:
    return send_from_directory("static/files", name, as_attachment=True)


def success() -> Response:
    return Response(status=200)


def require_auth(function: Callable) -> Callable:
    def page_wrapper(*args, **kwargs) -> Response:
        return function(*args, **kwargs) if session.check() else redirect("/auth")

    def api_wrapper(*args, **kwargs) -> Response:
        return function(*args, **kwargs) if session.check() else abort(403)

    wrapper = api_wrapper if function.__name__.startswith("api_") else page_wrapper
    # I hate python
    wrapper.__name__ = function.__name__
    return wrapper


@app.get("/auth")
def auth() -> Response:
    return page("index" if session.check() else "auth")


@app.get("/")
@require_auth
def index() -> Response:
    return page("index")


@app.get("/script")
@require_auth
def script() -> Response:
    return file("start_sploit.py")


@app.post("/api/auth")
def api_auth() -> Response:
    if (
        request.is_json
        and request.json is not None
        and (password := request.json.get("password"))
        and session.authenticate(password)
    ):
        return success()
    else:
        abort(403)


@app.route("/api/flags/<string:exploit>", methods=["POST", "PUT"])
@require_auth
def api_put_flags(exploit: str) -> Response:
    if not request.is_json or not isinstance(request.json, list):
        abort(400)
    flags.queue(exploit, request.json)
    return success()


@app.get("/api/flags")
@require_auth
def api_get_flags() -> Response:
    offset = int(request.args.get("start", 0))
    count = int(request.args.get("count", 10))
    if count > 100:
        abort(400)
    return jsonify(flags.query(offset, count))


@app.get("/api/config")
@require_auth
def api_config() -> Response:
    config = {
        "flagFormat": Config.flag_format,
        "flagLifetime": Config.flag_lifetime,
        "tickDuration": Config.tick_duration,
        "teams": Config.teams,
    }
    return jsonify(config)


@app.get("/api/attack")
@require_auth
def api_attack() -> Response:
    # TODO: Implement attack data caching
    abort(501)


@app.before_request
def log_request() -> None:
    log.info(f"-> {request.method} {request.full_path.strip("?")}")


@app.after_request
def log_response(response: Response) -> Response:
    log.info(f"<- HTTP {response.status}")
    return response
