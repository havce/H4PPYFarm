import sys

from typing import NoReturn
from timeutils import date


_COLOR_INFO = "\033[1;36m"
_COLOR_WARNING = "\033[1;33m"
_COLOR_ERROR = "\033[1;31m"
_COLOR_FATAL = "\033[1;41;97m"


def _p(*args, **kwargs):
    print(f"{date()} |", *args, "\033[0m", **kwargs, flush=True, file=sys.stderr)


def info(o: object, *args, **kwargs) -> None:
    _p(f"{_COLOR_INFO}[INFO]", str(o).strip(), *args, **kwargs)


def warning(o: object, *args, **kwargs) -> None:
    _p(f"{_COLOR_WARNING}[WARN]", str(o).strip(), *args, **kwargs)


def error(o: object, *args, **kwargs) -> None:
    _p(f"{_COLOR_ERROR}[ERRO]", str(o).strip(), *args, **kwargs)


def fatal(o: object, *args, **kwargs) -> NoReturn:
    _p(f"{_COLOR_FATAL}[CRIT]", str(o).strip(), *args, **kwargs)
    exit(-1)


def ensure(condition: bool, o: object, *args, **kwargs) -> NoReturn | None:
    if not condition:
        fatal(o, *args, **kwargs)
