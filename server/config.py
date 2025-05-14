import secrets
import re
import yaml
import log

from typing import Any, cast
from os import getenv
from hashlib import sha256


type ConfigValue = int | str | bytes | bool


class ConfigMeta(type):
    _RANGE_REGEX = re.compile("\\{([0-9]+\\.\\.[0-9]+)}")
    _DEFAULTS = {
        "address": "0.0.0.0",
        "port": 6969,
        "flag_lifetime": 5,
        "tick_duration": 120,
        "submit_period": 10,
        "submit_timeout": 10,
        "batch_limit": 1000,
        "database": ":memory:",
        "system_type": "forcad",
        "flag_format": "[A-Z0-9]{31}=",
        "hfi_source": "../hfi",
        "hfi_cache": "../hfi-cache",
    }

    _yaml_data = None

    @classmethod
    def _get_yaml_data(cls) -> Any:
        if cls._yaml_data is None:
            try:
                with open("farm.yml", "r") as f:
                    cls._yaml_data = yaml.safe_load(f)
            except (FileNotFoundError, yaml.YAMLError) as exc:
                if isinstance(exc, FileNotFoundError):
                    log.warning("No farm.yml file found!")
                else:
                    log.error("Could not parse farm.yaml")
                    log.error(exc)
                # Initialize the configuration with an empty dict
                cls._yaml_data = dict()
        return cls._yaml_data

    @classmethod
    def _get_env(cls, key: str) -> str | int | None:
        key = "FARM_" + key.upper()
        if not (val := getenv(key)) or len(val) == 0:
            return None
        try:
            # Try parsing the value as integer
            return int(val)
        except ValueError:
            return val

    @classmethod
    def _get_yaml(cls, key: str) -> Any:
        if data := cls._get_yaml_data():
            return data.get(key.replace("_", "-"))
        return None

    @classmethod
    def _get_value(cls, key: str) -> str | int:
        for function in [cls._get_env, cls._get_yaml]:
            if value := function(key):
                return value
        else:
            value = cls._DEFAULTS.get(key)
            log.ensure(
                value is not None,
                f"No default value exists for parameter '{key}'. Please provide one using environment variables or a farm.yml file!",
            )
            # Shut up linter
            assert value
            return value

    @classmethod
    def _getter_secret_key(cls) -> bytes:
        if not (key := cls._get_env("secret_key")):
            log.warning("No secret key provided. Generating a default one...")
            key = secrets.token_bytes(32)
            log.info(
                "You can specify a secret key using the FARM_SECRET_KEY environment variable"
            )
            return key
        else:
            return str(key).encode("ASCII")

    @classmethod
    def _getter_database(cls) -> str:
        if (value := str(cls._get_value("database"))) == ":memory:":
            log.warning("Using an in-memory database is discouraged!")
        return value

    @classmethod
    def _getter_teams(cls) -> list[str]:
        values = [str(cls._get_value("teams"))]
        groups = cls._RANGE_REGEX.findall(values[0])
        if len(groups) == 0:
            return values
        for group in groups:
            (start, end) = group.split("..")
            new_values = []
            for value in values:
                try:
                    for i in range(int(start), int(end) + 1):
                        new_values.append(value.replace(f"{{{group}}}", str(i)))
                except ValueError:
                    log.fatal(f"Invalid range '{value}'")
            values = new_values
        return values

    @classmethod
    def _getter_dev_mode(cls) -> bool:
        return cls._get_env("dev") is not None

    @classmethod
    def _ensure_type(cls, key: str, value: ConfigValue) -> ConfigValue:
        match key:
            case "password":
                return sha256(str(value).encode()).digest()
            case "team_token":
                return str(value)
            case "timeout":
                log.ensure(isinstance(value, int), "Timeout must be an integer")
            case "system_url":
                log.ensure(
                    isinstance(value, str) and "://" in value,
                    "No protocol specified in system URL!",
                )
        return value

    @classmethod
    def __getattr__(cls, key: str) -> ConfigValue:
        getter_name = f"_getter_{key}"
        if (getter := cast(type, cls).__dict__.get(getter_name)) and isinstance(
            getter, classmethod
        ):
            return cast(ConfigValue, getter.__func__(cls))
        else:
            return cls._ensure_type(key, cls._get_value(key))


# I fucking hate python
class Config(metaclass=ConfigMeta):
    pass


# Trigger checks for values that don't have defaults set
_ = Config.password
_ = Config.teams
_ = Config.system_url
