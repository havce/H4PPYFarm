#!/usr/bin/env python3
import math
import os
import re
import sys
from time import time, sleep
from requests import Session
from requests import ConnectionError
from json import JSONDecodeError
from subprocess import run as run_process, CalledProcessError, TimeoutExpired
from concurrent.futures import ThreadPoolExecutor


cfg = {}
flags = []
wave = 1

BLACK = 0
RED = 1
GREEN = 2
YELLOW = 3
BLUE = 4
MAGENTA = 5
CYAN = 6
WHITE = 7


def wprint(*args):
    print(f"[{wave:03d}]", *args)


def highlight(message: str, color: int):
    return f"\033[3{color}m{message}\033[0m"


def usage():
    print(f"""USAGE: {sys.argv[0]} [OPTIONS] EXPLOIT

The possible value for OPTIONS are:
  --server-url URL         The URL of the server running H4PPY Farm
  --server-pass PASSWORD   The password of the H4PPY Farm server
  --timeout TIMEOUT        The amount of time in seconds after which an instance of the exploit should be killed
  --help                   Print this message
    """)
    exit(-1)


def get_arg(arg_name: str, default: str | int | None) -> str | None:
    try:
        idx = sys.argv.index(f"--{arg_name}")
        if idx >= len(sys.argv) - 1:
            usage()
        return sys.argv[idx + 1]
    except ValueError:
        return default


def parse_args():
    if "--help" in sys.argv:
        usage()
    config_keys = {"server-url": None, "server-pass": None, "timeout": 10}
    for arg, default in config_keys.items():
        if not (arg_val := get_arg(arg, default)):
            if not default:
                usage()
            arg_val = default
        elif isinstance(default, int):
            arg_val = float(arg_val)
        cfg[arg] = arg_val
    cfg["exploit"] = os.path.join("./", sys.argv[-1])


def url_for(endpoint) -> str:
    url = cfg["server-url"]
    if not url.startswith("http://"):
        url = f"http://{url}"
    # This is probably not needed
    if url[-1] == "/" and endpoint[0] == "/":
        url = url[:-1]
    elif url[-1] != "/" and endpoint[0] != "/":
        url += "/"
    return f"{url}{endpoint}"


def authenticate() -> Session:
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


def check_exploit():
    exploit = cfg["exploit"]
    print(f"Checking exploit '{exploit}'...")
    try:
        with open(exploit, "r") as f:
            first_line = f.readline()
            # This check can be easily broken, I don't care
            if not first_line.startswith("#!/usr/bin/env python3"):
                print("Currently only python3 scripts are supported.\n"
                      "Please put '#!/usr/bin/env python3' in the first line of the file")
                exit(-1)
            source = "\n".join(f.readlines())
            if re.search(r'flush[(=]', source) is None:
                print("Please use print(..., flush=True) in your script, instead of just print(...)")
                exit(-1)
    except FileNotFoundError as exc:
        print(f"Could not open {exploit}: {exc}")
        exit(-1)


def run_exploit(team: str) -> list | None:
    try:
        flag_format = cfg["flag_format"]
        exploit = cfg["exploit"]
        timeout = cfg["timeout"] if cfg["timeout"] > 1 else 1
        output = run_process([exploit, team], capture_output=True, timeout=timeout, check=True).stdout.decode()
        run_flags = flag_format.findall(output)
        if len(run_flags) == 0:
            wprint(highlight(f"Got no flags for team {team}", MAGENTA))
        else:
            wprint(highlight(f"Got {len(run_flags)} flags from team {team}", GREEN))
            ts = time()
            return list(map(lambda x: {"flag": x, "ts": ts}, run_flags))
    except CalledProcessError:
        wprint(highlight(f"Exploit crashed on team {team}!", RED))
    except TimeoutExpired:
        wprint(highlight(f"Exploit timed-out on team {team}!", YELLOW))
    return None


def compute_n_workers(n_workers: int, deadline: float, wave_time: float) -> int:
    teams = cfg["teams"]

    teams_per_worker = math.ceil(len(teams) / n_workers)
    time_per_team = wave_time / teams_per_worker
    n_workers = math.ceil((time_per_team * len(teams)) / deadline)
    if n_workers > os.cpu_count():
        n_workers = os.cpu_count()
    expected_time = (time_per_team * len(teams)) / n_workers

    wprint(f"{teams_per_worker = }, {time_per_team = :.2f}s, {n_workers = }, {expected_time = :.2f}s")

    return n_workers


def run_exploit_on_teams(n_workers: int) -> (float, list):
    global flags
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


def send_flags(session: Session):
    try:
        exploit = cfg["exploit"]
        exploit_name = os.path.basename(exploit).split(".")[0]
        res = session.post(url_for(f"/api/flags/{exploit_name}"), json=flags)
        if res.status_code != 200:
            wprint(highlight("Could not send flags, am I not authenticated?", YELLOW))
        else:
            flags.clear()
    except ConnectionError:
        wprint(highlight("Could not send flags, I will send them later.", YELLOW))


def main():
    global wave

    parse_args()
    check_exploit()
    session = authenticate()
    print("Retrieving config...")
    get_config(session)

    n_workers = os.cpu_count()
    deadline = cfg["tick_duration"] * 0.5

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
            flags.extend(wave_flags)
            send_flags(session)
            wave_time = time() - start
            wprint(f"Took {wave_time:.2f} seconds, recomputing parameters...")
            n_workers = compute_n_workers(n_workers, deadline, wave_time)
            wait_time = deadline - wave_time
            if wait_time > 0:
                wprint(f"Sleeping for {wait_time:.2f}s")
                sleep(wait_time)
            else:
                wprint(highlight("Your exploit is very slow! Speed it up!", YELLOW))
            get_config(session)  # Refresh config
            wave += 1
    except KeyboardInterrupt:
        print("Ctrl+C detected, exiting...")


if __name__ == "__main__":
    main()
