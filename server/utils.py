from time import sleep


def _print(msg):
    print(msg, flush=True)


def info(msg):
    _print(f"[INFO] {msg}")


def warning(msg):
    _print(f"[WARN] {msg}")


def error(msg):
    _print(f"[ERRO] {msg}")


def thread_yield():
    sleep(0)
