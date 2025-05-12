import flags

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import String, SmallInteger, BigInteger
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from timeutils import time


class Base(DeclarativeBase):
    pass


class Flags(Base):
    __tablename__ = "flags"

    flag: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    exploit: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    timestamp: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    submission_timestamp: Mapped[int] = mapped_column(BigInteger(), nullable=True)
    system_message = mapped_column(String(128), nullable=True)

    def submit_result(self, status: int | None, system_message: str | None):
        self.status = status or flags.STATUS_UNKNOWN
        self.system_message = system_message or "Unknown message"
        self.submission_timestamp = time()


db = SQLAlchemy(model_class=Base)
