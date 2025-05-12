from time import time as get_time
from datetime import datetime

_FMT = "%Y-%m-%d %H:%M:%S"


def date() -> str:
    return datetime.now().strftime(_FMT)


def time() -> int:
    return int(get_time())


def time_to_date(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp).strftime(_FMT)
