from json import JSONDecodeError
import log
import flags
import requests

from time import sleep
from flask import Flask
from config import Config
from database import db, Flags
from timeutils import time
from abc import ABC, abstractmethod


_SUBMIT_TIMEOUT = int(Config.submit_timeout)
_SUBMIT_PERIOD = int(Config.submit_period)
_SYSTEM_TYPE = str(Config.system_type)
_SYSTEM_URL = str(Config.system_url)
_TEAM_TOKEN = str(Config.team_token)


class SubmitterResponse(object):
    def __init__(self, flag: str, status: int, message: str):
        self.flag = flag
        self.status = status
        self.message = message


class Submitter(ABC):
    @abstractmethod
    def __init__(self) -> None:
        pass

    @abstractmethod
    def _send(self, batch: list[Flags]) -> None:
        pass

    def send(self, batch: list[Flags]) -> None:
        self._send(batch)
        db.session.commit()


class SubmitterForcAD(Submitter):
    _STATUS_MAP = {
        "ACCEPTED": flags.STATUS_ACCEPTED,
        "DENIED": flags.STATUS_REJECTED,
        "RESUBMIT": flags.STATUS_REJECTED,
        "ERROR": flags.STATUS_REJECTED,
        "UNKNOWN": flags.STATUS_UNKNOWN,
    }

    def __init__(self) -> None:
        log.ensure(
            _SYSTEM_URL.startswith("http://") or _SYSTEM_URL.startswith("https://"),
            "Game system is set to ForcAD, but the submitter does not use the HTTP protocol",
        )

    def _parse_response(self, flags_map: dict[str, Flags], obj: dict[str, str]) -> None:
        if (flag := obj.get("flag")) and (flags_entry := flags_map.get(flag)):
            status = obj.get("status", "UNKNOWN")
            status = self._STATUS_MAP.get(status, flags.STATUS_UNKNOWN)
            message = obj.get("msg", "Unknown message")
            message = message.split("] ", 1)[-1]
            flags_entry.submit_result(status, message)

    def _do_send(self, batch: list[Flags]) -> None:
        flags_map = {x.flag: x for x in batch}
        # Send flags to server
        response = requests.put(
            _SYSTEM_URL,
            headers={"X-Team-Token": _TEAM_TOKEN},
            json=list(flags_map.keys()),
            timeout=_SUBMIT_TIMEOUT,
        )
        response = response.json()
        # Ensure the response looks valid
        if not isinstance(response, list):
            raise TypeError(f"Expected list, got {type(response).__name__}")
        # Convert response objects to common format
        for obj in response:
            self._parse_response(flags_map, obj)

    def _send(self, batch: list[Flags]) -> None:
        try:
            self._do_send(batch)
        # Invalid response format
        except TypeError as e:
            log.error(f"Invalid system response. {e}")
        # Invalid response JSON
        except requests.JSONDecodeError:
            log.error(f"Could not decode system response")
        # Connection errors
        except requests.Timeout:
            log.error(f"Request to game system timed out")
        except requests.ConnectionError:
            log.error(f"Could not connect to game system")
        except (requests.HTTPError, requests.TooManyRedirects):
            log.error(f"An HTTP error occurred")
        except requests.RequestException:
            log.error(f"An error occurred while building the request")


_submitter = (
    constructor()
    if (constructor := ({"forcad": SubmitterForcAD}).get(_SYSTEM_TYPE.lower()))
    else log.fatal(f"Unknown game system type {_SYSTEM_TYPE}")
)


def _do_submit() -> int:
    batch = flags.next_batch()
    if len(batch) > 0:
        log.info(f"Submitting {len(batch)} flags to game system")
        _submitter.send(batch)
        # Find the time until the next expiration
        next_expiration = flags.LIFETIME - (time() - batch[-1].timestamp)
        return min(_SUBMIT_PERIOD, next_expiration)
    else:
        return _SUBMIT_PERIOD


def task(app: Flask) -> None:
    last_submission = 0
    sleepy_time = 0
    while True:
        with app.app_context():
            # Expire flags
            flags.mark_expired()
            # Submit next batch
            if (now := time()) - last_submission >= _SUBMIT_PERIOD:
                last_submission = now
                sleepy_time = _do_submit()
            else:
                sleepy_time = _SUBMIT_PERIOD - (now - last_submission)
        sleep(sleepy_time)
