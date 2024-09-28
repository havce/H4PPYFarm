import sqlite3
from queue import Queue

from config import cfg
from threading import Thread, Lock, Condition


class SQLRequest(object):
    _NEXT_ID = 0
    _LOCK = Lock()

    def __init__(self, query: str | None, args: tuple | list[tuple] | None, f):
        self.query = query
        self.args = args if args else ()
        self.f = f
        with SQLRequest._LOCK:
            self.id = SQLRequest._NEXT_ID
            SQLRequest._NEXT_ID += 1

    def is_many(self):
        return isinstance(self.args, list)


class Database(Thread):
    def __init__(self):
        super().__init__()
        self._db = None
        self._cur = None
        self._queue = Queue()
        self._results = {}
        self._result_ready = Condition()
        self._run = False

    def _open_database(self):
        self._db = sqlite3.connect(cfg.database)
        self._cur = self._db.cursor()

    def _close_database(self):
        self._db.commit()
        self._db.close()

    def run(self):
        self._open_database()

        while self._run:
            req = self._queue.get()
            if isinstance(req, int) and req == 0xdeadbeef:
                self._db.commit()
                continue

            assert isinstance(req, SQLRequest), "Not an SQL request"

            if req.is_many():
                res = self._cur.executemany(req.query, req.args)
            else:
                res = self._cur.execute(req.query, req.args)
            res = res.fetchall()

            if req.f:
                res = map(lambda x: req.f(*x), res)
            res = list(res)

            self._results[req.id] = res
            with self._result_ready:
                self._result_ready.notify_all()

        self._close_database()

    def start(self):
        self._run = True
        super().start()

    def join(self, **kwargs):
        self._run = False
        super().join(**kwargs)

    def _fetch_result(self, req_id: int):
        while not (req_id in self._results):
            with self._result_ready:
                self._result_ready.wait()
        return self._results.pop(req_id)

    def execute(self, query: str, args: tuple | list[tuple] | None = None, f = None):
        req = SQLRequest(query, args, f)
        self._queue.put(req)
        return self._fetch_result(req.id)

    def commit(self):
        self._queue.put(0xdeadbeef)


db = Database()
