import secrets
import re
import yaml
from os import getenv
from utils import info, warning, error

defaults = {
    "port": 6969,
    "flag_lifetime": 5,
    "tick_duration": 120,
    "submit_period": 10,
    "batch_limit": 1000,
    "database": ":memory:",
    "flag_format": "[A-Z0-9]{31}=",
    "timeout": 10
}


class Config(object):
    _RANGE = re.compile("{([0-9]*\\.\\.[0-9]*)}")

    def __init__(self):
        self._cfg_file = None
        try:
            with open("farm.yml", "r") as f:
                try:
                    self._cfg_file = yaml.safe_load(f)
                except yaml.YAMLError as exc:
                    error(exc)
        except FileNotFoundError:
            warning("No farm.yml file found!")

    @staticmethod
    def _get_env(key):
        val = getenv("FARM_" + key.upper())
        if not val or len(val) == 0:
            return None
        try:
            # Try parsing the value as integer
            val = int(val)
        except ValueError:
            pass
        return val

    def _get_cfg(self, key):
        if self._cfg_file:
            return self._cfg_file.get(key.replace("_", "-"))
        return None

    def _get_param(self, key) -> str | int:
        for fn in [self._get_env, self._get_cfg]:
            val = fn(key)
            if val:
                return val
        val = defaults.get(key)
        assert val, f"""
            No default value exists for parameter '{key}'.
            Please provide one using environment variables or a farm.yml file!
        """
        return val

    @property
    def secret_key(self) -> bytes:
        key = self._get_env("secret_key")
        if not key:
            warning("No secret key provided. Generating a default one...")
            key = secrets.token_bytes(32)
            info("You can specify a secret key using the FARM_SECRET_KEY environment variable")
        else:
            key = str(key).encode("ASCII")
        return key

    @property
    def database(self) -> str:
        val = str(self._get_param("database"))
        if val == ":memory:":
            warning("Using an in-memory database is discouraged!")
        return val

    @property
    def teams(self) -> list[str]:
        value = str(self._get_param("teams"))
        if match := Config._RANGE.search(value):
            assert len(match.groups()) == 1, f"Invalid range '{value}'"
            (start, end) = match.group(1).split("..")
            fmt = value
            values = []
            try:
                for i in range(int(start), int(end) + 1):
                    values.append(Config._RANGE.sub(str(i), fmt))
                return values
            except ValueError:
                assert False, f"Invalid range '{fmt}'"

    def __getattr__(self, item) -> str | int:
        val = self._get_param(item)
        match item:
            case "password" | "team_token":
                return str(val)
            case "timeout":
                assert isinstance(val, int), "Timeout must be an integer"
            case "system_url":
                assert isinstance(val, str) and "://" in val, "No protocol specified in system URL!"
        return val


cfg = Config()
