import math
import re
import requests
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

    _REGISTER_FLAG = 0
    _REGISTER_SUBMISSION = 1
    _SELECT_FLAGS = 2
    _SLICE = 3
    _COMMIT = 4

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
                case FlagStore._REGISTER_FLAG:
                    self._register_flag(req["flag"], req["exploit"], req["timestamp"])
                    res = True

                case FlagStore._REGISTER_SUBMISSION:
                    self._register_submission(req["flag"], req["timestamp"], req["accepted"], req["message"])
                    res = True

                case FlagStore._SELECT_FLAGS:
                    res = self._select_flags_by_status(req["status"], req["count"])

                case FlagStore._SLICE:
                    res = self._slice(req["start"], req["count"])

                case FlagStore._COMMIT:
                    self._db.commit()
                    res = True

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

    def commit(self):
        self._request_sync(FlagStore._COMMIT, {})

    def register_flag(self, flag: str, exploit: str, timestamp: float):
        self._request_sync(FlagStore._REGISTER_FLAG, {
            "flag": flag,
            "exploit": exploit,
            "timestamp": timestamp
        })

    def _register_flag(self, flag: str, exploit: str, timestamp: float):
        try:
            self._cur.execute("""
            INSERT INTO flags (flag, exploit, timestamp, status)
            VALUES (?, ?, ?, ?)
            """, (flag, exploit, math.floor(timestamp), PENDING))
        except sqlite3.IntegrityError:
            warning(f"Duplicate flag {flag}")

    def register_submission(self, flag: str, timestamp: float, accepted: bool | None, message: str):
        self._request_sync(FlagStore._REGISTER_SUBMISSION, {
            "flag": flag,
            "timestamp": timestamp,
            "accepted": accepted,
            "message": message
        })

    def _register_submission(self, flag: str, timestamp: float, accepted: bool | None, message: str):
        status = ACCEPTED if accepted else UNKNOWN if accepted is None else REJECTED
        self._cur.execute("""
        UPDATE flags
        SET status = ?, submission_timestamp = ?, system_message = ?
        WHERE flag = ?
        """, (status, math.floor(timestamp), message, flag))

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
    TEAM_TOKEN = cfg.team_token
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
        entries = self._normalize_user_submitted_data(flags)
        info(f"Submitted {len(entries)} valid flags from exploit '{exploit}'")
        for entry in entries:
            ts = entry["ts"] if "ts" in entry else time()
            if ts + FlagStore.FLAG_LIFETIME > time():
                self._store.register_flag(entry["flag"], exploit, ts)
        self._store.commit()

    def run(self):
        while self._run:
            batch = self._next_batch()
            if len(batch) == 0:
                thread_yield()
                continue
            if self._submit(batch):
                sleep(5)  # On failure, retry after 5 seconds
                continue
            sleep(FlagSubmitter.SUBMIT_PERIOD)

    def _next_batch(self) -> list:
        return self._store.select_flags_by_status(PENDING, FlagSubmitter.BATCH_LIMIT)

    @staticmethod
    def _normalize_system_response_data(responses) -> list:
        if not isinstance(responses, list):
            if not isinstance(responses, dict):
                raise requests.exceptions.JSONDecodeError()
            responses = [responses]
        return list(filter(lambda x: "flag" in x, responses))

    # `received` can be one of the following:
    # ["flag_value1", "flag_value2"]
    # {"flag": "flag_value"} or {"flag": "flag_value", "ts", timestamp}
    # [{"flag": "flag_value1"}, {"flag": "flag_value2", "ts", timestamp}]
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
        try:
            ts = time()
            res = requests.put(
                FlagSubmitter.SYSTEM_URL,
                headers={"X-Team-Token": FlagSubmitter.TEAM_TOKEN},
                json=flags)
            try:
                submissions = self._normalize_system_response_data(res.json())
                for submission in submissions:
                    flag = submission["flag"]
                    accepted = submission.get("status", None)
                    message = submission.get("msg", "No message from the system")
                    self._store.register_submission(flag, ts, accepted, message)
                self._store.commit()
                info(f"Submitted {len(flags)} flags to {FlagSubmitter.SYSTEM_URL}")
            except requests.exceptions.JSONDecodeError:
                error(f"Invalid server response: {res.text}")
            return False
        except requests.ConnectionError:
            error(f"An error occurred while connecting to the system ({FlagSubmitter.SYSTEM_URL}).")
            info("Retrying in 5 seconds...")
        except Exception as exc:
            error(exc)  # I don't know if requests.put() can throw any other exception, but I don't care, catch 'em all.
        return True


flag_store = FlagStore()
flag_submitter = FlagSubmitter(flag_store)
