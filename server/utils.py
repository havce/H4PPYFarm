from time import sleep


def _print(*args):
    print(*args, "\033[0m", flush=True)


def info(*args):
    _print(f"\033[36m[INFO]", *args)


def warning(*args):
    _print(f"\033[33m[WARN]", *args)


def error(*args):
    _print(f"\033[31m[ERRO]", *args)


def thread_yield():
    sleep(0)
