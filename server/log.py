import sys
from typing import NoReturn

_COLOR_INFO = "\033[1;36m"
_COLOR_WARNING = "\033[1;33m"
_COLOR_ERROR = "\033[1;31m"
_COLOR_FATAL = "\033[1;41;97m"


def _p(*args):
    print(*args, "\033[0m", flush=True, file=sys.stderr)


def info(o: object, *args) -> None:
    _p(f"{_COLOR_INFO}[INFO]", str(o).strip(), *args)


def warning(o: object, *args) -> None:
    _p(f"{_COLOR_WARNING}[WARN]", str(o).strip(), *args)


def error(o: object, *args) -> None:
    _p(f"{_COLOR_ERROR}[ERRO]", str(o).strip(), *args)


def fatal(o: object, *args) -> NoReturn:
    _p(f"{_COLOR_FATAL}[CRIT]", str(o).strip(), *args)
    exit(-1)


def ensure(condition: bool, o: object, *args) -> NoReturn | None:
    if not condition:
        fatal(o, *args)
