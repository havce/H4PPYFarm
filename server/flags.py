import math
import re
import select

import requests
import socket
from threading import Thread
from time import time, sleep

from config import cfg
from db import db
from utils import info, warning, error


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

    def __init__(self):
        super().__init__()
        self._run = False

    def run(self):
        FlagStore._create_table()
        while self._run:
            sleep(5)
            self._mark_expired()

    def start(self):
        self._run = True
        super().start()

    def join(self, **kwargs):
        self._run = False
        super().join(**kwargs)

    @staticmethod
    def _create_table():
        db.execute("""
        CREATE TABLE IF NOT EXISTS flags (
            flag                 VARCHAR(64) NOT NULL,
            exploit              VARCHAR(64),
            timestamp            INTEGER,
            status               INTEGER,
            submission_timestamp INTEGER,
            system_message       VARCHAR(128),
            PRIMARY KEY (flag)
        )""")
        db.commit()

    @staticmethod
    def _mark_expired():
        now = time()
        db.execute(f"""
        UPDATE flags
        SET status = {EXPIRED}, submission_timestamp = {now}, system_message = 'Expired'
        WHERE status = {PENDING} AND timestamp + ? <= {now}
        """, (FlagStore.FLAG_LIFETIME,))
        db.commit()

    @staticmethod
    def register_flags(flags: list[dict[str, str | float]], exploit: str):
        data = list(map(lambda x: (x["flag"], exploit, x["ts"], PENDING), flags))
        db.execute("""
        INSERT OR IGNORE INTO flags (flag, exploit, timestamp, status)
        VALUES (?, ?, ?, ?)
        """, data)
        db.commit()

    @staticmethod
    def register_submissions(submissions: list, timestamp: float):
        ts = math.floor(timestamp)

        def to_db_entry(sub) -> (int, int, str, str):
            accepted = sub.get("status", None)
            message = sub.get("msg", "No message from system")
            status = ACCEPTED if accepted else UNKNOWN if accepted is None else REJECTED
            return status, ts, message, sub["flag"]

        data = list(map(to_db_entry, submissions))
        db.execute("""
        UPDATE flags
        SET status = ?, submission_timestamp = ?, system_message = ?
        WHERE flag = ?
        """, data)
        db.commit()

    @staticmethod
    def select_flags_by_status(status: int, count: int) -> list[str]:
        res = db.execute("""
        SELECT flag FROM flags WHERE status = ? LIMIT ?
        """, (status, count))
        return list(map(lambda x: x[0], res))

    @staticmethod
    def slice(start: int, count: int) -> list[dict[str, str | float | int]]:
        def f(flag, exploit, timestamp, status, submission_timestamp, system_message):
            lifetime = submission_timestamp if submission_timestamp else time()
            lifetime -= timestamp
            return {
                "flag": flag,
                "exploit": exploit,
                "timestamp": timestamp,
                "lifetime": lifetime,
                "status": status,
                "submission_timestamp": submission_timestamp,
                "system_message": system_message
            }

        return db.execute("""
        SELECT * FROM flags ORDER BY timestamp DESC LIMIT ? OFFSET ?
        """, (count, start), f)


class FlagSubmitter(Thread):
    BATCH_LIMIT = cfg.batch_limit
    SUBMIT_PERIOD = cfg.submit_period
    SYSTEM_URL = cfg.system_url
    TIMEOUT = cfg.timeout
    FLAG_FORMAT = re.compile(f"^{cfg.flag_format}$")

    def __init__(self):
        super().__init__()
        self._run = False

    def start(self):
        self._run = True
        super().start()

    def join(self, **kwargs):
        self._run = False
        super().join(**kwargs)

    def queue(self, exploit: str, flags: list[str]):
        now = time()

        def ensure_ts(entry: dict[str, str | float]) -> dict[str, str | float]:
            if not ("ts" in entry):
                entry["ts"] = now
            return entry

        entries = self._normalize_user_submitted_data(flags)
        info(f"Submitted {len(entries)} valid flags from exploit '{exploit}'")
        entries = list(filter(lambda x: now - x["ts"] < FlagStore.FLAG_LIFETIME, map(ensure_ts, entries)))
        FlagStore.register_flags(entries, exploit)

    def run(self):
        while self._run:
            batch = FlagSubmitter._next_batch()
            if len(batch) == 0 or not self._submit(batch):
                sleep(5)  # on idle or on failure, retry after 5 seconds
                continue
            sleep(FlagSubmitter.SUBMIT_PERIOD)

    @staticmethod
    def _next_batch() -> list[str]:
        return FlagStore.select_flags_by_status(PENDING, FlagSubmitter.BATCH_LIMIT)

    @staticmethod
    def _normalize_user_submitted_data(submissions) -> list[dict[str, str | float]]:
        # if `arr` is not a list then it must be a dict, otherwise it's invalid
        if not isinstance(submissions, list):
            if not isinstance(submissions, dict):
                raise requests.exceptions.JSONDecodeError()
            submissions = [submissions]
        normalized = map(lambda x: {"flag": x} if isinstance(x, str) else x, submissions)
        normalized = filter(lambda x: isinstance(x, dict) and "flag" in x, normalized)
        normalized = filter(lambda x: not (FlagSubmitter.FLAG_FORMAT.match(x["flag"]) is None), normalized)
        return list(normalized)

    def _submit(self, flags: list[str]) -> bool:
        ts = time()
        submissions = self.do_submit(flags)
        if submissions:
            assert isinstance(submissions, list), "FlagSubmitter.do_submit() should always return a list"
            info(f"Submitted {len(flags)} flags to {FlagSubmitter.SYSTEM_URL}")
            FlagStore.register_submissions(submissions, ts)
            return True
        return False

    def do_submit(self, flag: list[str]) -> list[dict[str, str | bool]] | None:
        raise NotImplementedError()


class FlagSubmitterHttp(FlagSubmitter):
    def __init__(self):
        super().__init__()
        self._team_token = cfg.team_token
        self._message_regex = re.compile(f"\\[{cfg.flag_format}]", re.MULTILINE)

    def _normalize_system_response_data(self, responses: list[dict[str, str | bool] | dict[str, str | bool]]) \
            -> list[dict[str, str | bool]]:
        if not isinstance(responses, list):
            if not isinstance(responses, dict):
                raise requests.exceptions.JSONDecodeError()
            responses = [responses]
        sanitized = list(filter(lambda x: "flag" in x, responses))
        for entry in sanitized:
            entry["msg"] = self._message_regex.sub("", entry["msg"]).strip()
        return sanitized

    def do_submit(self, flags: list[str]) -> list[dict[str, str | bool]] | None:
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
        except Exception as exc:
            error(exc)  # I don't know if requests.put() can throw any other exception, but I don't care, catch 'em all.
        return None


class FlagSubmitterTcp(FlagSubmitter):
    def __init__(self):
        super().__init__()
        self._flag_format = re.compile(cfg.flag_format)
        ip_and_port = FlagSubmitter.SYSTEM_URL.split("://", 1)[1].split(":", 1)
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
    def _normalize_system_response_data(response: str, flag: str) -> dict[str, str | bool]:
        message = response.strip()
        if " " in message:
            # ENOWARS game systems sends back the flag and a message
            flag, message = response.split(" ", 1)
        status = message in "OK"
        return {"flag": flag, "msg": message, "status": status}

    def do_submit(self, flags: list[str]) -> list[dict[str, str | bool]] | None:
        try:
            sock = socket.create_connection(self._address, timeout=FlagSubmitter.TIMEOUT)
            submissions = []
            for flag in flags:
                sock.send(flag.encode())
                ready = select.select([sock], [], [], FlagSubmitter.TIMEOUT)
                if ready[0]:
                    # we assume the server will not reply with more than 4096 bytes of data at a time
                    resp = sock.recv(4096)
                    if len(resp) == 0:
                        # the client has disconnected, abort
                        break
                    try:
                        response = resp.decode()
                    except UnicodeDecodeError:
                        # invalid system response
                        response = "UNKNOWN"
                    submission = FlagSubmitterTcp._normalize_system_response_data(response, flag)
                    submissions.append(submission)
            sock.close()
            if len(submissions) == 0:
                return None
            elif len(submissions) < len(flags):
                warning("Server returned less flags than the ones I submitted")
            return submissions
        except TimeoutError:
            error(f"Server connection timed-out ({self._address[0]}:{self._address[1]})")
            return None


def get_flag_submitter() -> FlagSubmitter:
    sys_url = FlagSubmitter.SYSTEM_URL
    proto = sys_url.split("://")[0]
    if proto == "http" or proto == "https":
        return FlagSubmitterHttp()
    elif proto == "tcp":
        return FlagSubmitterTcp()
    else:
        assert False, f"Unsupported protocol {proto}"


flag_store = FlagStore()
flag_submitter = get_flag_submitter()
