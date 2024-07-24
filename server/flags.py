import math
import re
import select

import requests
import socket
import sqlite3
from queue import Queue
from threading import Thread, get_ident
from time import time, sleep
from config import cfg
from utils import info, warning, error, thread_yield


PENDING = 0
EXPIRED = 1
UNKNOWN = 2
ACCEPTED = 3
REJECTED = 4


class FlagStore(Thread):
    FLAG_LIFETIME = cfg.flag_lifetime * cfg.tick_duration

    _REGISTER_FLAGS = 0
    _REGISTER_SUBMISSION = 1
    _SELECT_FLAGS = 2
    _SLICE = 3

    _MESSAGE_REGEX = re.compile(f"\\[{cfg.flag_format}]", re.MULTILINE)

    def __init__(self):
        super().__init__()
        self._run = False
        self._requests = Queue()
        self._responses = {}
        self._db = None
        self._cur = None

    def run(self):
        self._open_database()

        last_cleanup = time()
        while self._run:
            if self._requests.qsize() == 0:
                if time() - last_cleanup > 10:
                    self._mark_expired()
                    last_cleanup = time()
                thread_yield()
                continue

            res = False
            req = self._requests.get()
            req_id = req["id"]

            match req["op"]:
                case FlagStore._REGISTER_FLAGS:
                    self._register_flags(req["flag"], req["exploit"])
                    res = True

                case FlagStore._REGISTER_SUBMISSION:
                    self._register_submissions(req["submissions"], req["timestamp"])
                    res = True

                case FlagStore._SELECT_FLAGS:
                    res = self._select_flags_by_status(req["status"], req["count"])

                case FlagStore._SLICE:
                    res = self._slice(req["start"], req["count"])

            self._responses[req_id] = res

        self._close_database()

    def start(self):
        self._run = True
        super().start()

    def join(self, **kwargs):
        self._run = False
        super().join(**kwargs)

    def _open_database(self):
        self._db = sqlite3.connect(cfg.database)
        self._cur = self._db.cursor()
        self._cur.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            flag                 VARCHAR(64) NOT NULL,
            exploit              VARCHAR(64),
            timestamp            INTEGER,
            status               INTEGER,
            submission_timestamp INTEGER,
            system_message       VARCHAR(128),
            PRIMARY KEY (flag)
        )""")
        self._db.commit()

    def _close_database(self):
        self._db.commit()
        self._db.close()

    def _mark_expired(self):
        now = time()
        self._cur.execute(f"""
        UPDATE flags
        SET status = {EXPIRED}, submission_timestamp = {now}, system_message = 'Expired'
        WHERE status = {PENDING} AND timestamp + ? <= {now}
        """, (FlagStore.FLAG_LIFETIME,))
        self._db.commit()

    def _request_sync(self, op: int, data: dict) -> bool | list:
        req_id = get_ident()
        data["op"] = op
        data["id"] = req_id
        self._requests.put(data)
        while not (req_id in self._responses):
            thread_yield()
        return self._responses.pop(req_id)

    def register_flags(self, flags: list, exploit: str):
        self._request_sync(FlagStore._REGISTER_FLAGS, {
            "flag": flags,
            "exploit": exploit,
        })

    def _register_flags(self, flags: list, exploit: str):
        data = list(map(lambda x: (x["flag"], exploit, x["ts"], PENDING), flags))
        self._cur.executemany("""
        INSERT OR IGNORE INTO flags (flag, exploit, timestamp, status)
        VALUES (?, ?, ?, ?)
        """, data)
        self._db.commit()

    def register_submissions(self, submissions: list, timestamp: float):
        self._request_sync(FlagStore._REGISTER_SUBMISSION, {
            "submissions": submissions,
            "timestamp": timestamp
        })

    def _register_submissions(self, submissions: list, timestamp: float):
        ts = math.floor(timestamp)

        def to_db_entry(sub) -> (int, int, str, str):
            accepted = sub.get("status", None)
            message = sub.get("msg", "No message from system")
            message = FlagStore._MESSAGE_REGEX.sub("", message).strip()
            status = ACCEPTED if accepted else UNKNOWN if accepted is None else REJECTED
            return status, ts, message, sub["flag"]

        data = list(map(to_db_entry, submissions))
        self._cur.executemany("""
        UPDATE flags
        SET status = ?, submission_timestamp = ?, system_message = ?
        WHERE flag = ?
        """, data)
        self._db.commit()

    def select_flags_by_status(self, status: int, count: int) -> list:
        return self._request_sync(FlagStore._SELECT_FLAGS, {
            "status": status,
            "count": count
        })

    def _select_flags_by_status(self, status: int, count: int) -> list:
        res = self._cur.execute("""
        SELECT flag FROM flags WHERE status = ? LIMIT ?
        """, (status, count))
        return list(map(lambda x: x[0], res.fetchall()))

    def slice(self, start: int, count: int) -> list:
        return self._request_sync(FlagStore._SLICE, {
            "start": start,
            "count": count
        })

    def _slice(self, start: int, count: int) -> list:
        res = self._cur.execute("""
        SELECT * FROM flags ORDER BY timestamp DESC LIMIT ? OFFSET ?
        """, (count, start))
        sliced = []
        for (flag, exploit, timestamp, status, submission_timestamp, system_message) in res.fetchall():
            lifetime = submission_timestamp if submission_timestamp else time()
            lifetime -= timestamp
            sliced.append({
                "flag": flag,
                "exploit": exploit,
                "timestamp": timestamp,
                "lifetime": lifetime,
                "status": status,
                "submission_timestamp": submission_timestamp,
                "system_message": system_message
            })
        return sliced


class FlagSubmitter(Thread):
    BATCH_LIMIT = cfg.batch_limit
    SUBMIT_PERIOD = cfg.submit_period
    SYSTEM_URL = cfg.system_url
    TIMEOUT = cfg.timeout
    FLAG_FORMAT = re.compile(f"^{cfg.flag_format}$")

    def __init__(self, store: FlagStore):
        super().__init__()
        self._run = False
        self._store = store

    def start(self):
        self._run = True
        super().start()

    def join(self, **kwargs):
        self._run = False
        super().join(**kwargs)

    def queue(self, exploit: str, flags: list):
        now = time()

        def ensure_ts(entry: dict) -> dict:
            if not ("ts" in entry):
                entry["ts"] = now
            return entry

        entries = self._normalize_user_submitted_data(flags)
        info(f"Submitted {len(entries)} valid flags from exploit '{exploit}'")
        entries = list(filter(lambda x: now - x["ts"] < FlagStore.FLAG_LIFETIME, map(ensure_ts, entries)))
        self._store.register_flags(entries, exploit)

    def run(self):
        while self._run:
            batch = self._next_batch()
            if len(batch) == 0:
                thread_yield()
                continue
            if not self._submit(batch):
                sleep(5)  # On failure, retry after 5 seconds
                continue
            sleep(FlagSubmitter.SUBMIT_PERIOD)

    def _next_batch(self) -> list:
        return self._store.select_flags_by_status(PENDING, FlagSubmitter.BATCH_LIMIT)

    @staticmethod
    def _normalize_user_submitted_data(submissions) -> list:
        # if `arr` is not a list then it must be a dict, otherwise it's invalid
        if not isinstance(submissions, list):
            if not isinstance(submissions, dict):
                raise requests.exceptions.JSONDecodeError()
            submissions = [submissions]
        normalized = map(lambda x: {"flag": x} if isinstance(x, str) else x, submissions)
        normalized = filter(lambda x: isinstance(x, dict) and "flag" in x, normalized)
        normalized = filter(lambda x: not (FlagSubmitter.FLAG_FORMAT.match(x["flag"]) is None), normalized)
        return list(normalized)

    def _submit(self, flags: list) -> bool:
        ts = time()
        submissions = self.do_submit(flags)
        if submissions:
            assert isinstance(submissions, list), "FlagSubmitter.do_submit() should always return a list"
            info(f"Submitted {len(flags)} flags to {FlagSubmitter.SYSTEM_URL}")
            self._store.register_submissions(submissions, ts)
            return True
        return False

    def do_submit(self, flag: list[str]) -> list | None:
        raise NotImplementedError()


class FlagSubmitterHttp(FlagSubmitter):
    def __init__(self, store: FlagStore):
        super().__init__(store)
        self._team_token = cfg.team_token

    @staticmethod
    def _normalize_system_response_data(responses) -> list:
        if not isinstance(responses, list):
            if not isinstance(responses, dict):
                raise requests.exceptions.JSONDecodeError()
            responses = [responses]
        return list(filter(lambda x: "flag" in x, responses))

    def do_submit(self, flags: list[str]) -> list | None:
        try:
            res = requests.put(
                FlagSubmitter.SYSTEM_URL,
                headers={"X-Team-Token": self._team_token},
                json=flags,
                timeout=FlagSubmitter.TIMEOUT)
            try:
                return self._normalize_system_response_data(res.json())
            except requests.exceptions.JSONDecodeError:
                error(f"Invalid server response: {res.text}")
        except requests.ConnectionError:
            error(f"An error occurred while connecting to the system ({FlagSubmitter.SYSTEM_URL}).")
            info("Retrying in 5 seconds...")
        except Exception as exc:
            error(exc)  # I don't know if requests.put() can throw any other exception, but I don't care, catch 'em all.
        return None


class FlagSubmitterTcp(FlagSubmitter):
    def __init__(self, store: FlagStore):
        super().__init__(store)
        self._flag_format = re.compile(cfg.flag_format)
        ip_and_port = FlagSubmitter.SYSTEM_URL.split("://")[1].split(":")
        ip = ip_and_port[0]
        port = ip_and_port[1] if len(ip_and_port) > 1 else 1337
        try:
            self._address = (ip, int(port))
        except ValueError:
            error(f"Invalid port for TCP protocol: {port}")
            exit(-1)
        if len(ip_and_port) < 2:
            warning("No port specified for TCP protocol, defaulting to 1337")

    @staticmethod
    def _normalize_system_response_data(submissions: iter) -> list[dict[str, str | bool]]:
        def to_normalized(sub: str):
            flag, message = sub.split(" ")[:2]
            status = message.upper() == "OK"
            return {"flag": flag, "msg": message, "status": status}

        return list(map(to_normalized, submissions))

    def do_submit(self, flags: list[str]) -> list[dict[str, str | bool]] | None:
        try:
            sock = socket.create_connection(self._address, timeout=FlagSubmitter.TIMEOUT)
            sock.setblocking(False)
            payload = "\n".join(flags)
            sock.sendall(payload.encode())
            submissions = []
            buf = b""
            while len(submissions) < len(flags):
                try:
                    ready = select.select([sock], [], [], 10)
                    if ready[0]:
                        buf += sock.recv(4096)
                except TimeoutError:
                    pass
                if len(buf) == 0:
                    # client has disconnected?
                    break
                recv_flags = buf.split(b"\n")
                buf = recv_flags.pop()
                full_flags = map(lambda x: x.decode(), recv_flags)
                full_flags = filter(lambda x: self._flag_format.search(x), full_flags)
                submissions.extend(full_flags)
            sock.close()
            if len(submissions) == 0:
                return None
            elif len(submissions) < len(flags):
                warning("Server returned less flags than the ones I submitted")
            return self._normalize_system_response_data(submissions)
        except TimeoutError:
            error(f"Server connection timed-out ({self._address[0]}:{self._address[1]})")
            return None


def get_flag_submitter(store: FlagStore):
    sys_url = FlagSubmitter.SYSTEM_URL
    proto = sys_url.split("://")[0]
    if proto.startswith("http"):
        return FlagSubmitterHttp(store)
    elif proto.startswith("tcp"):
        return FlagSubmitterTcp(store)
    else:
        assert False, f"Unsupported protocol {proto}"


flag_store = FlagStore()
flag_submitter = get_flag_submitter(flag_store)
