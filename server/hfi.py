import os
import shutil
import subprocess
from subprocess import CalledProcessError

from config import cfg
from utils import error, info, warning
from db import db


class HfiManager(object):
    _SOURCE = cfg.hfi_source
    _CACHE = cfg.hfi_cache
    _TARGETS = {
        "linux": {
            "x86_64": "x86_64-unknown-linux-musl"
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
    def get_checkers() -> list[dict[str, str | int]]:
        services = []
        def f(service_name, port, delta):
            services.append({
                "service": service_name,
                "port": port,
                "delta": delta
            })
        db.execute("SELECT service_name, port, delta FROM hfi", f=f)
        return services

    @staticmethod
    def add_checker(checker: dict[str, str | int]):
        service = checker.get("service", "unknown")
        port = checker["port"]
        delta = checker["delta"]
        db.execute("""
        INSERT OR IGNORE INTO hfi (service_name, port, delta)
        VALUES (?, ?, ?)
        """, (service, port, delta))
        db.commit()

    @staticmethod
    def remove_checker(checker: dict[str, int]):
        delta = checker["delta"]
        db.execute("""
        DELETE FROM hfi WHERE delta = ?
        """, (delta,))
        db.commit()

    @staticmethod
    def _get_bin_path(req_os: str, req_arch: str) -> str:
        bin_path = os.path.join(HfiManager._CACHE, f"hfi-{req_os}-{req_arch}")
        if req_os == "windows":
            bin_path += ".exe"
        return bin_path

    @staticmethod
    def _get_cached_build(req_os: str, req_arch: str):
        bin_path = HfiManager._get_bin_path(req_os, req_arch)
        return bin_path if os.access(bin_path, os.R_OK) else None

    @staticmethod
    def _get_src_path() -> str:
        assert os.access(HfiManager._SOURCE, os.R_OK), "Cannot access hfi source path"
        return HfiManager._SOURCE

    @staticmethod
    def _get_src_dir() -> str:
        src_dir = os.path.join(HfiManager._get_src_path(), "src")
        assert os.access(src_dir, os.R_OK)
        return src_dir

    @staticmethod
    def _get_target_triple(req_os: str, req_arch: str) -> str | None:
        if triples_for_os := HfiManager._TARGETS.get(req_os):
            return triples_for_os.get(req_arch)
        return None

    @staticmethod
    def _compile_bin(req_os: str, req_arch: str) -> bool:
        if not (triple := HfiManager._get_target_triple(req_os, req_arch)):
            error(f"No target triple exists for {req_os}/{req_arch}")
            return False
        else:
            info(f"Compiling hfi for {req_os}/{req_arch}")
        args = [
            "cargo",
            "build",
            "--release",
            "--target", triple
        ]
        bin_path = HfiManager._get_bin_path(req_os, req_arch)
        src_path = HfiManager._get_src_path()
        try:
            subprocess.check_output(args, cwd=src_path, stderr=subprocess.STDOUT)
            artifact_path = os.path.join(src_path, "target", triple, "release", "hfi")
            shutil.move(artifact_path, bin_path)
            return True
        except CalledProcessError as exc:
            error(f"Could not compile hfi for triple {triple}")
            if exc.output:
                for line in exc.output.decode().split("\n"):
                    warning(line)
            return False

    @staticmethod
    def get(req_os: str, req_arch: str, try_compile = True) -> str | None:
        bin_path = HfiManager._get_cached_build(req_os, req_arch)
        if bin_path:
            info(f"Found hfi build for {req_os}/{req_arch}")
            src_dir = HfiManager._get_src_dir()
            if os.stat(bin_path).st_mtime >= os.stat(src_dir).st_mtime:
                return bin_path
        if try_compile:
            # if there is no build available or the cached version is out of date,
            # rebuild hfi for the requested arch
            if HfiManager._compile_bin(req_os, req_arch):
                return HfiManager.get(req_os, req_arch, try_compile=False)
        warning(f"No hfi build found for {req_os}/{req_arch}")
        return None

    @staticmethod
    def timestamp() -> int | None:
        try:
            if path := HfiManager._get_src_dir():
                stat_data = os.stat(path)
                return int(stat_data.st_mtime)
        except OSError:
            pass
        return None
