from flask import session
from hashlib import sha256
from config import Config
from timeutils import time


# A session can last up to 72hrs
SESSION_LIFETIME = 72 * 60 * 60


def authenticate(password: str) -> bool:
    if auth := sha256(password.encode()).digest() == Config.password:
        session["expires"] = time() + SESSION_LIFETIME
    session["auth"] = auth
    return auth


def check() -> bool:
    return (
        session.get("auth") is True
        and (expires := session.get("expires")) is not None
        and expires > time()
    )
