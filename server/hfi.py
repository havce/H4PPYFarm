import os
import shutil
import subprocess
from subprocess import CalledProcessError, DEVNULL

from config import cfg
from utils import error, info, warning
from db import db


class HfiManager(object):
    _SOURCE = cfg.hfi_source
    _CACHE = cfg.hfi_cache
    _TARGETS = {
        "linux": {
            "x86_64": "x86_64-unknown-linux-gnu"
        }
    }

    @staticmethod
    def create_table():
        db.execute("""
        CREATE TABLE IF NOT EXISTS hfi (
            service_name         VARCHAR(32) NOT NULL,
            port                 INTEGER,
            delta                INTEGER,
            PRIMARY KEY (delta)
        )""")
        db.commit()

    @staticmethod
    def get_checkers() -> dict[int, list[int]]:
        services = {}
        def f(port, delta):
            if not (port in services):
                services[port] = [delta]
            else:
                services[port].append(delta)
        db.execute("SELECT port, delta FROM hfi", f=f)
        return services

    @staticmethod
    def add_checkers(checkers: list[dict[str, str | int]]):
        data = []
        for checker in checkers:
            service = checker.get("service", "unknown")
            port = checker["port"]
            delta = checker["delta"]
            data.append((service, port, delta))
        db.execute("""
        INSERT OR IGNORE INTO hfi (service_name, port, delta)
        VALUES (?, ?, ?)
        """, data)
        db.commit()

    @staticmethod
    def _get_bin_path(req_os: str, req_arch: str) -> str | None:
        bin_path = os.path.join(HfiManager._CACHE, f"hfi-{req_os}-{req_arch}")
        if req_os == "windows":
            bin_path += ".exe"
        src_path = HfiManager._get_src_path()
        if not os.access(bin_path, os.R_OK) or os.stat(bin_path).st_mtime < os.stat(src_path).st_mtime:
            if not HfiManager._compile_bin(req_os, req_arch, src_path, bin_path):
                return None
        return bin_path if os.access(bin_path, os.R_OK) else None

    @staticmethod
    def _get_src_path() -> str:
        assert os.access(HfiManager._SOURCE, os.R_OK), "Cannot access hfi source path"
        return HfiManager._SOURCE

    @staticmethod
    def _get_target_triple(req_os: str, req_arch: str) -> str | None:
        if triples_for_os := HfiManager._TARGETS.get(req_os):
            return triples_for_os.get(req_arch)
        return None

    @staticmethod
    def _compile_bin(req_os: str, req_arch: str, src_path: str, bin_path: str) -> bool:
        if not (triple := HfiManager._get_target_triple(req_os, req_arch)):
            error(f"No target triple exists for {req_os}/{req_arch}")
            return False
        args = [
            "cargo",
            "build",
            "--release",
            "--target", triple
        ]
        try:
            subprocess.check_output(args, cwd=src_path, stderr=subprocess.STDOUT)
            artifact_path = os.path.join(src_path, "target", triple, "release", "hfi")
            shutil.move(artifact_path, bin_path)
            return True
        except CalledProcessError as exc:
            error(f"Could not compile hfi for triple {triple}")
            if exc.output:
                error(exc.output)
            return False

    @staticmethod
    def get(req_os: str, req_arch: str) -> str | None:
        bin_path = HfiManager._get_bin_path(req_os, req_arch)
        if bin_path:
            info(f"Found hfi build for {req_os}/{req_arch}")
            return bin_path
        else:
            warning(f"No hfi build found for {req_os}/{req_arch}")
            return None

    @staticmethod
    def timestamp(req_os: str, req_arch: str) -> int | None:
        path = HfiManager._get_bin_path(req_os, req_arch)
        try:
            stat_data = os.stat(path)
            return int(stat_data.st_mtime)
        except OSError:
            return None
