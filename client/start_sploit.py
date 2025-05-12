#!/usr/bin/env python3
import math
import os
import re
import sys
import platform
import shutil
from random import randint
from time import time, sleep

from requests import Session, ConnectionError
from json import JSONDecodeError
from subprocess import run as run_process, Popen, CalledProcessError, TimeoutExpired
from concurrent.futures import ThreadPoolExecutor

this_os = platform.system().lower()
this_arch = platform.machine()

# global configuration
params = {}  # client configuration
cfg = {}  # server configuration

# wave state
wave = 1

# failure filter
failure_counters = {}

BLACK = 0
RED = 1
GREEN = 2
YELLOW = 3
BLUE = 4
MAGENTA = 5
CYAN = 6
WHITE = 7


def set_proc_name(name: str):
    if this_os == "linux":
        from ctypes import cdll, byref, create_string_buffer

        name_bytes = name.encode("ASCII")
        libc = cdll.LoadLibrary("libc.so.6")
        buff = create_string_buffer(len(name_bytes) + 1)
        buff.value = name_bytes
        # PRCTL_SET_NAME = 15
        libc.prctl(15, byref(buff), 0, 0, 0)


def wprint(*args):
    global wave
    print(f"[{wave:03d}]", *args)


def highlight(message: str, color: int):
    return f"\033[3{color}m{message}\033[0m"


def usage():
    print(f"""USAGE: {sys.argv[0]} [OPTIONS] EXPLOIT

The possible value for OPTIONS are:
  --server-url URL         The URL of the server running H4PPY Farm.
  --server-pass PASSWORD   The password of the H4PPY Farm server.
  --timeout TIMEOUT        The amount of time in seconds after which an instance of the exploit should be killed.
  --always-retry           Always try exploit on targets on which it always seems to fail.
  --failure-threshold N    The number of consecutive failures for one team, after which the script should start
                           decreasing the probability of running the exploit on that one team.
  --max-failures MAX       The maximum amount of failures after which the probability of running the exploit stops
                           decreasing.
  --help                   Print this message.
    """)
    exit(-1)


def get_arg(
    arg_name: str, default: str | int | None, is_switch: bool
) -> str | bool | None:
    try:
        idx = sys.argv.index(f"--{arg_name}")
        if is_switch:
            return not default
        elif idx >= len(sys.argv) - 1:
            usage()
        return sys.argv[idx + 1]
    except ValueError:
        return default


def parse_args():
    global params

    if "--help" in sys.argv:
        usage()

    config_keys = {
        "server-url": None,
        "server-pass": None,
        "timeout": 10,
        "fake-timestamps": False,
        "always-retry": False,
        "max-failures": 12,
        "failure-threshold": 4,
    }

    for arg, default in config_keys.items():
        if not (arg_val := get_arg(arg, default, isinstance(default, bool))):
            if default is None:
                usage()
            arg_val = default
        elif isinstance(default, int | float):
            arg_val = float(arg_val)
        params[arg] = arg_val
    params["exploit"] = os.path.join("./", sys.argv[-1])


def url_for(endpoint) -> str:
    global params

    url = params["server-url"]
    if not (url.startswith("http") and "://" in url):
        url = f"http://{url}"
    # this is probably not needed
    if url[-1] == "/" and endpoint[0] == "/":
        url = url[:-1]
    elif url[-1] != "/" and endpoint[0] != "/":
        url += "/"
    return f"{url}{endpoint}"


def authenticate() -> Session:
    global params

    print(
        f"Authenticating on {url_for('/api/auth')} with password ({'*' * len(params['server-pass'])})..."
    )
    try:
        session = Session()
        res = session.post(
            url_for("/api/auth"), json={"password": params["server-pass"]}
        )
        if res.status_code != 200:
            print(
                highlight("Authentication failed. Is the server password correct?", RED)
            )
            exit(-1)
        return session
    except ConnectionError:
        print(highlight(f"Could not communicate with the H4PPY Farm server.", RED))
        exit(-1)


def get_config(session: Session):
    global cfg

    try:
        res = session.get(url_for("/api/config"))
        remote_cfg = res.json()
        for key, val in remote_cfg.items():
            if key == "flagFormat":
                cfg[key] = re.compile(val, re.MULTILINE)
            else:
                cfg[key] = val
    except ConnectionError:
        print("Could not retrieve configuration, continuing anyways...")
    except JSONDecodeError:
        print("Could not decode configuration JSON, continuing anyways...")

    if not ("teams" in cfg):
        print("No configuration loaded!")
        exit(-1)
    else:
        for team in filter(lambda x: not (x in failure_counters), cfg["teams"]):
            failure_counters[team] = 0


def linux_set_capabilities(file: str, caps: list[str]) -> bool:
    if len(caps) == 0:
        return True
    root_utils = {"pkexec": ["--keep-cwd"], "sudo": [], "doas": []}
    for util in root_utils.keys():
        if util_path := shutil.which(util):
            util_args = [util_path, *root_utils[util]]
            break
    else:
        return False

    caps = ",".join(caps)
    try:
        print(
            highlight(
                f"We need your permission to set the following capabilities for the file '{file}': {caps}",
                GREEN,
            )
        )
        run_process(
            [*util_args, "setcap", caps + "+ep", file], check=True, capture_output=True
        )
        return True
    except CalledProcessError:
        return False


def get_temporary_dir() -> str:
    if this_os == "windows":
        temp_dir = os.getenv("Temp", ".")
    else:
        temp_dir = "/tmp"
        if not os.access(temp_dir, os.W_OK):
            temp_dir = "."
    return temp_dir


def get_persistent_dir() -> str:
    if this_os == "windows":  # eww
        pers_dir = os.getenv("Temp", ".")
    else:
        pers_dir = "."
        if home_dir := os.getenv("HOME"):
            pers_dir2 = os.path.join(home_dir, ".cache")
            if os.access(pers_dir2, os.W_OK):
                pers_dir = pers_dir2
    return pers_dir


def get_hfi(session: Session) -> str | None:
    global params, this_os, this_arch

    hfi_url = url_for(f"/hfi/{this_os}/{this_arch}")
    file_name = "hfi.exe" if this_os == "windows" else "hfi"
    pers_dir = get_persistent_dir()
    exe_path = os.path.join(pers_dir, file_name)

    try:
        # get local version timestamp
        stat_data = os.stat(exe_path)
        local_timestamp = int(stat_data.st_mtime)
        # get server version timestamp
        server_timestamp = None
        res = session.get(url_for(f"/hfi/timestamp"))
        if res.status_code != 200:
            print(highlight(f"Cannot get hfi timestamp (error {res.status_code})", RED))
        else:
            try:
                server_timestamp = res.json().get("timestamp")
            except JSONDecodeError:
                print(highlight("Invalid hfi timestamp", YELLOW))

        print(server_timestamp, local_timestamp)
        if server_timestamp and server_timestamp > local_timestamp:
            print(highlight("New version of hfi found!", GREEN))
        # use the local version of the hfi, if we can't get a timestamp from the server or
        # if the local version is newer than the one on the server
        elif os.access(exe_path, os.X_OK):
            return exe_path
    except FileNotFoundError:
        print(highlight("Local version of hfi not found!", YELLOW))

    print(highlight("Downloading hfi from server...", YELLOW))

    # download hfi
    res = session.get(hfi_url)
    if res.status_code != 200:
        print(highlight("Could not get hfi executable from server", RED))
        return None

    # save the file
    try:
        with open(exe_path, "wb") as f:
            f.write(res.content)
        os.chmod(exe_path, 0o755)
        if os.access(exe_path, os.X_OK):
            if this_os == "linux":
                if linux_set_capabilities(exe_path, ["cap_net_admin"]):
                    return exe_path
                else:
                    print(highlight("Could not set capabilities", RED))
        else:
            print(highlight("Could not make file executable", RED))
    except FileNotFoundError | OSError:
        print(highlight(f"Could not write executable to {exe_path}!", RED))
        print(highlight("Does the current user have access to it?", YELLOW))
    return None


def launch_hfi(session: Session):
    global params

    if not (hfi_path := get_hfi(session)):
        print(
            highlight("Cannot fake timestamps. Continue anyways? [y/N]", YELLOW),
            end=" > ",
        )
        if (input() or "n").lower() != "y":
            exit(-1)
        return

    temp_dir = get_temporary_dir()
    log_file = f"hfi-log-{int(time())}"
    log_path = os.path.join(temp_dir, log_file)
    server_url = params["server-url"]
    server_pass = params["server-pass"]
    args = [hfi_path, "--server-url", server_url, "--server-password", server_pass]

    try:
        with open(log_path, "wb") as log_fd:
            print(highlight(f"TCP packet interceptor log @ {log_path}", CYAN))
            proc = Popen(args, stdout=log_fd, stderr=log_fd, start_new_session=True)
            proc.wait(0.5)
            if proc.returncode != 0:
                print(highlight("Could not launch TCP packet interceptor", RED))
                exit(-1)
    except TimeoutExpired:
        pass


def check_exploit():
    global params

    exploit = params["exploit"]
    print(f"Checking exploit '{exploit}'...")
    try:
        with open(exploit, "r") as f:
            source = "\n".join(f.readlines())
            if re.search(r"flush\s*=\s*True", source) is None:
                print(
                    "Please use print(..., flush=True) in your script, instead of just print(...)"
                )
                exit(-1)
    except FileNotFoundError as exc:
        print(f"Could not open {exploit}: {exc}")
        exit(-1)


def run_exploit(team: str) -> list[dict[str, str | float]] | None:
    global failure_counters, params, cfg

    failure_threshold = params["failure-threshold"]
    # FIXME: Figure out why the fuck failure_counters[team] becomes a fucking float
    if randint(0, int(failure_counters[team])) > failure_threshold:
        # decrease the possibility of running the exploit on teams on which the exploit seems to fail the most
        wprint(highlight(f"Not running exploit on {team} (too many failures)", YELLOW))
        return None
    flag_format = cfg["flagFormat"]
    exploit = params["exploit"]
    timeout = params["timeout"] if params["timeout"] > 1 else 1
    # FIXME: Do NOT run all exploits with python3 by default. Check whether the file is a binary
    #        or a script and either use the correct interpreter or refuse to run the file and
    #        exit with an error.
    args = ["python3", exploit, team]

    try:
        output = run_process(
            args, capture_output=True, timeout=timeout, check=True
        ).stdout.decode()
        run_flags = flag_format.findall(output)
        if len(run_flags) == 0:
            wprint(highlight(f"Got no flags for team {team}", MAGENTA))
        else:
            if failure_counters[team] > failure_threshold:
                failure_counters[team] = failure_threshold  # give it another chance
            elif failure_counters[team] > 0:
                failure_counters[team] -= 1
            wprint(highlight(f"Got {len(run_flags)} flags from team {team}", GREEN))
            ts = time()
            return list(map(lambda x: {"flag": x, "ts": ts}, run_flags))
    except CalledProcessError:
        wprint(highlight(f"Exploit crashed on team {team}!", RED))
    except TimeoutExpired:
        wprint(highlight(f"Exploit timed-out on team {team}!", YELLOW))
    if failure_counters[team] < params["max-failures"]:
        failure_counters[team] += 1
    return None


def get_attack_data():
    global cfg

    attack_data_url = params["attack_data_url"]
    if not attack_data_url:
        wprint(highlight(f"No attack data url provided", YELLOW))
        return None
    if not (attack_data_url.startswith("http") and "://" in attack_data_url):
        wprint(highlight(f"Attack data url not supported! {attack_data_url}", RED))
        return None

    # TODO finish implementing this


def compute_n_workers(n_workers: int, deadline: float, wave_time: float) -> int:
    global cfg

    teams = cfg["teams"]

    wave_time = math.ceil(wave_time)
    teams_per_worker = math.ceil(len(teams) / n_workers)
    time_per_team = wave_time / teams_per_worker
    n_workers = math.ceil((time_per_team * len(teams)) / deadline)
    if n_workers > os.cpu_count():
        n_workers = os.cpu_count()
    expected_time = (time_per_team * len(teams)) / n_workers

    wprint(
        f"{teams_per_worker = }, {time_per_team = :.2f}s, {n_workers = }, {expected_time = :.2f}s"
    )

    return n_workers


def run_exploit_on_teams(n_workers: int) -> (float, list[dict[str, str | float]]):
    global cfg

    fails = 0
    teams = cfg["teams"]
    wave_flags = []
    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        this_flags = executor.map(run_exploit, teams)
        for run_flags in this_flags:
            if run_flags:
                wave_flags.extend(run_flags)
            else:
                fails += 1
    return fails, wave_flags


def send_flags(session: Session, flags: list[str]) -> bool:
    global params

    try:
        exploit = params["exploit"]
        exploit_name, _ = os.path.basename(exploit).split(".", 1)
        res = session.post(
            url_for(f"/api/flags/{exploit_name}"), json=flags, timeout=10
        )
        if res.status_code == 200:
            return True
        wprint(highlight("Could not send flags, am I not authenticated?", YELLOW))
    except ConnectionError:
        wprint(highlight("Could not send flags, I will send them later.", YELLOW))
    return False


def main():
    global wave, params

    parse_args()
    set_proc_name("start_sploit")
    check_exploit()
    session = authenticate()
    print("Retrieving config...")
    get_config(session)
    if params["fake-timestamps"]:
        launch_hfi(session)

    n_workers = os.cpu_count()
    deadline = cfg["tickDuration"] * 0.5

    flags = []
    try:
        while True:
            print()
            wprint(f"Beginning new run...")
            start = time()
            # TODO finish this
            # attack_data = get_attack_data()
            fails, wave_flags = run_exploit_on_teams(n_workers)
            wprint(f"Run finished, got {len(wave_flags)} flags")
            wprint(f"Exploit failed on {fails} teams")
            if len(wave_flags) == 0:
                wprint(highlight(f"Got 0 flags, something's broken!", YELLOW))
            # send flags
            flags.extend(wave_flags)
            if send_flags(session, flags):
                flags.clear()  # only clear the flags array if we managed to send all the flags
            # end wave and recompute parameters
            wave_time = time() - start
            wprint(f"Took {wave_time:.2f} seconds, recomputing parameters...")
            n_workers = compute_n_workers(n_workers, deadline, wave_time)
            # wait for next the  wave to start
            wait_time = deadline - wave_time
            if wait_time > 0:
                wprint(f"Sleeping for {wait_time:.2f}s")
                sleep(wait_time)
            else:
                wprint(highlight("Your exploit is very slow! Speed it up!", YELLOW))
            get_config(session)  # refresh config
            wave += 1
    except KeyboardInterrupt:
        print("Ctrl+C detected, exiting...")


if __name__ == "__main__":
    main()
