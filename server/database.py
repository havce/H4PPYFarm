import math
import hashlib
import secrets

from time import time
from base64 import b64encode, b64decode
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import String, SmallInteger, BigInteger
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import Config
from . import log


class Base(DeclarativeBase):
    pass


class Flags(Base):
    _LIFETIME = Config.flag_lifetime

    _STATUS_PENDING = 0
    _STATUS_EXPIRED = 1
    _STATUS_UNKNOWN = 2
    _STATUS_ACCEPTED = 3
    _STATUS_REJECTED = 4

    __tablename__ = "flags"

    flag: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    exploit: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[int] = mapped_column(SmallInteger())
    timestamp: Mapped[int] = mapped_column(BigInteger())
    submission_timestamp: Mapped[int] = mapped_column(BigInteger())
    system_message = mapped_column(String(128))

    @classmethod
    def mark_expired(cls):
        now = int(time())
        db.session.execute(
            db.update(cls)
            .where(
                cls.status == cls._STATUS_PENDING
                and cls.timestamp + cls._LIFETIME <= now
            )
            .values(
                status=cls._STATUS_EXPIRED,
                submission_timestamp=now,
                system_message="Expired",
            )
        )
        db.session.commit()


class Sessions(Base):
    _NONCE_SIZE = 32
    # A session can last up to 72 hrs
    _LIFETIME = 72 * 60 * 60

    __tablename__ = "sessions"

    remote_address: Mapped[str] = mapped_column(String(40), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(math.ceil(_NONCE_SIZE * 4 / 3)))
    expiry_timestamp: Mapped[int] = mapped_column(BigInteger())

    @classmethod
    def create(cls, remote_address: str) -> bytes:
        nonce = secrets.token_bytes(cls._NONCE_SIZE)
        nonce_b64 = b64encode(nonce)
        log.ensure(
            len(nonce_b64) < math.ceil(cls._NONCE_SIZE * 4 / 3),
            "Base64 encoded nonce is too big!",
        )
        expiry_timestamp = int(time()) + cls._LIFETIME
        (session,) = (
            Sessions(
                remote_address=remote_address,
                nonce=b64encode(nonce),
                expiry_timestamp=expiry_timestamp,
            ),
        )
        db.session.add(session)
        return session._generate_token()

    def _generate_token(self) -> bytes:
        return hashlib.sha256(
            self.remote_address.encode() + b64decode(self.nonce)
        ).digest()

    def verify(self, token: bytes) -> bool:
        return token == self._generate_token()


db = SQLAlchemy(model_class=Base)
