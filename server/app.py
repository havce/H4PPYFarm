#!/usr/bin/env python3

from flask import Flask, abort
from waitress import serve

from .config import Config
from .database import db, Flags

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{Config.database}"
app.secret_key = Config.secret_key

db.init_app(app)


@app.get("/")
def index():
    Flags.mark_expired()
    abort(403)


def app_init() -> None:
    with app.app_context():
        db.create_all()


def main():
    app_init()
    serve(app, host=Config.address, port=Config.port)


if __name__ == "__main__":
    main()
