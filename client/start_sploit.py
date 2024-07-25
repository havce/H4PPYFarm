#!/usr/bin/env python3
import math
import os
import re
import sys
from random import randint
from time import time, sleep
from requests import Session, ConnectionError
from json import JSONDecodeError
from subprocess import run as run_process, CalledProcessError, TimeoutExpired
from concurrent.futures import ThreadPoolExecutor


# global configuration
cfg = {}

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


def get_arg(arg_name: str, default: str | int | None, is_switch: bool) -> str | bool | None:
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
    global cfg

    if "--help" in sys.argv:
        usage()
    config_keys = {
        "server-url": None,
        "server-pass": None,
        "timeout": 10,
        "always-retry": False,
        "max-failures": 12,
        "failure-threshold": 4
    }
    for arg, default in config_keys.items():
        if not (arg_val := get_arg(arg, default, isinstance(default, bool))):
            if default is None:
                usage()
            arg_val = default
        elif isinstance(default, int | float):
            arg_val = float(arg_val)
        cfg[arg] = arg_val
    cfg["exploit"] = os.path.join("./", sys.argv[-1])


def url_for(endpoint) -> str:
    global cfg

    url = cfg["server-url"]
    if not (url.startswith("http") and "://" in url):
        url = f"http://{url}"
    # this is probably not needed
    if url[-1] == "/" and endpoint[0] == "/":
        url = url[:-1]
    elif url[-1] != "/" and endpoint[0] != "/":
        url += "/"
    return f"{url}{endpoint}"


def authenticate() -> Session:
    global cfg

    print(f"Authenticating on {url_for('/api/auth')} with password ({'*' * len(cfg['server-pass'])})...")
    try:
        session = Session()
        res = session.post(url_for("/api/auth"), json={"password": cfg["server-pass"]})
        if res.status_code != 200:
            print(highlight("Authentication failed. Is the server password correct?", RED))
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
        for (key, val) in remote_cfg.items():
            if key == "flag_format":
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


def check_exploit():
    global cfg

    exploit = cfg["exploit"]
    print(f"Checking exploit '{exploit}'...")
    try:
        with open(exploit, "r") as f:
            source = "\n".join(f.readlines())
            if re.search(r'flush\s*=\s*True', source) is None:
                print("Please use print(..., flush=True) in your script, instead of just print(...)")
                exit(-1)
    except FileNotFoundError as exc:
        print(f"Could not open {exploit}: {exc}")
        exit(-1)


def run_exploit(team: str) -> list[dict[str, str | float]] | None:
    global failure_counters, cfg

    failure_threshold = cfg["failure-threshold"]
    if randint(0, failure_counters[team]) > failure_threshold:
        # decrease the possibility of running the exploit on teams on which the exploit seems to fail the most
        wprint(highlight(f"Not running exploit on {team} (too many failures)", YELLOW))
        return None
    flag_format = cfg["flag_format"]
    exploit = cfg["exploit"]
    timeout = cfg["timeout"] if cfg["timeout"] > 1 else 1
    args = ["python3", exploit, team]

    try:
        # FIXME: Do NOT run all exploits with python3 by default. Check whether the file is a binary
        #        or a script and either use the correct interpreter or refuse to run the file and
        #        exit with an error.
        output = run_process(args, capture_output=True, timeout=timeout, check=True).stdout.decode()
        run_flags = flag_format.findall(output)
        if len(run_flags) == 0:
            wprint(highlight(f"Got no flags for team {team}", MAGENTA))
        else:
            if failure_counters[team] > failure_threshold:
                failure_counters[team] = failure_threshold  # give it another chance
            else:
                failure_counters[team] -= 1
            wprint(highlight(f"Got {len(run_flags)} flags from team {team}", GREEN))
            ts = time()
            return list(map(lambda x: {"flag": x, "ts": ts}, run_flags))
    except CalledProcessError:
        wprint(highlight(f"Exploit crashed on team {team}!", RED))
    except TimeoutExpired:
        wprint(highlight(f"Exploit timed-out on team {team}!", YELLOW))
    if failure_counters[team] < cfg["max-failures"]:
        failure_counters[team] += 1
    return None


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

    wprint(f"{teams_per_worker = }, {time_per_team = :.2f}s, {n_workers = }, {expected_time = :.2f}s")

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
    global cfg

    try:
        exploit = cfg["exploit"]
        exploit_name, _ = os.path.basename(exploit).split(".", 1)
        res = session.post(url_for(f"/api/flags/{exploit_name}"), json=flags, timeout=10)
        if res.status_code == 200:
            return True
        wprint(highlight("Could not send flags, am I not authenticated?", YELLOW))
    except ConnectionError:
        wprint(highlight("Could not send flags, I will send them later.", YELLOW))
    return False


def main():
    global wave

    parse_args()
    check_exploit()
    session = authenticate()
    print("Retrieving config...")
    get_config(session)

    n_workers = os.cpu_count()
    deadline = cfg["tick_duration"] * 0.5

    flags = []
    try:
        while True:
            print()
            wprint(f"Beginning new run...")
            start = time()
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
