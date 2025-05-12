import log

from typing import Any
from config import Config
from database import db, Flags
from timeutils import time, time_to_date


_BATCH_LIMIT = int(Config.batch_limit)

LIFETIME = int(Config.flag_lifetime) * int(Config.tick_duration)

STATUS_PENDING = 0
STATUS_EXPIRED = 1
STATUS_UNKNOWN = 2
STATUS_ACCEPTED = 3
STATUS_REJECTED = 4


def mark_expired() -> None:
    now = time()
    expire_threshold = now - LIFETIME
    log.info(f"Expiring all flags older than {time_to_date(expire_threshold)}")
    db.session.execute(
        db.update(Flags)
        .where((Flags.status == STATUS_PENDING) & (Flags.timestamp <= expire_threshold))
        .values(
            status=STATUS_EXPIRED,
            submission_timestamp=now,
            system_message="Expired",
        )
    )
    db.session.commit()


def submit(exploit: str, user_data: Any) -> int:
    def normalize_user_data(data: Any) -> Flags | None:
        if isinstance(data, str):
            return Flags(
                exploit=exploit, flag=data, timestamp=time(), status=STATUS_PENDING
            )
        elif isinstance(data, dict) and isinstance(data.get("flag"), str):
            return Flags(
                exploit=exploit,
                flag=data["flag"],
                timestamp=data.get("ts", time()),
                status=STATUS_PENDING,
            )
        else:
            return None

    submitted_flags = list(
        filter(lambda x: x is not None, map(normalize_user_data, user_data)),
    )
    log.info(f"Submitted {len(submitted_flags)} for exploit {exploit}")

    db.session.add_all(submitted_flags)
    db.session.commit()

    return len(submitted_flags)


def query(offset: int, count: int):
    def convert_objects_to_json(flag: Flags) -> dict:
        submission_timestamp = (
            flag.submission_timestamp
            if flag.submission_timestamp is not None and flag.submission_timestamp > 0
            else None
        )
        lifetime = (submission_timestamp or time()) - flag.timestamp
        # NOTE: JSON uses camelCase, we use snake_case, so this is going to look a bit weird
        return {
            "flag": flag.flag,
            "exploit": flag.exploit,
            "status": flag.status,
            "timestamp": flag.timestamp,
            "submissionTimestamp": submission_timestamp,
            "systemMessage": flag.system_message,
            "lifetime": lifetime,
        }

    flags = db.session.execute(
        db.select(Flags).order_by(Flags.timestamp.desc()).limit(count).offset(offset)
    ).scalars()
    return list(map(convert_objects_to_json, flags))


def next_batch() -> list[Flags]:
    return list(
        db.session.execute(
            db.select(Flags)
            .where(Flags.status == STATUS_PENDING)
            .order_by(Flags.timestamp.asc())
            .limit(_BATCH_LIMIT)
        ).scalars()
    )
