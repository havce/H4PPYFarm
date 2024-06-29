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
avg_wave_time = 0


def usage():
    print(f"""USAGE: {sys.argv[0]} [OPTIONS] EXPLOIT

The possible value for OPTIONS are:
  --server-url URL         The URL of the server running H4PPY Farm
  --server-pass PASSWORD   The password of the H4PPY Farm server
  --timeout TIMEOUT        The amount of time in seconds after which an instance of the exploit should be killed
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
            print("Authentication failed. Is the server password correct?")
            exit(-1)
        return session
    except ConnectionError as exc:
        print(f"Could not communicate with the H4PPY Farm server.")
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
        output = run_process([exploit, team], capture_output=True, timeout=timeout).stdout.decode()
        run_flags = flag_format.findall(output)
        if len(run_flags) == 0:
            print(f"Got no flags for team {team}")
        else:
            print(f"Got {len(run_flags)} flags from team {team}")
            ts = time()
            return list(map(lambda x: {"flag": x, "ts": ts}, run_flags))
    except CalledProcessError:
        print(f"Exploit crashed on team {team}!")
    except TimeoutExpired:
        print(f"Exploit timed-out on team {team}!")
    return None


def compute_parameters(wave_time: float, wave: int) -> (int, float):
    global avg_wave_time
    deadline = cfg["tick_duration"] * 0.5

    avg_wave_time = ((avg_wave_time * (wave - 1)) + wave_time) / wave
    n_workers = math.ceil(avg_wave_time / deadline)
    if n_workers > os.cpu_count():
        n_workers = os.cpu_count()

    wait_time = deadline - avg_wave_time
    if wait_time < 0:
        print("Your exploit is very slow, speed it up!")
        wait_time = 0

    return n_workers, wait_time


def run_exploit_on_teams(n_workers: int) -> (float, int):
    global flags
    fails = 0
    teams = cfg["teams"]
    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        this_flags = executor.map(run_exploit, teams)
        for run_flags in this_flags:
            if run_flags:
                flags.extend(run_flags)
            else:
                fails += 1
    return fails


def send_flags(session: Session):
    try:
        exploit = cfg["exploit"]
        exploit_name = os.path.basename(exploit).split(".")[0]
        res = session.post(url_for(f"/api/flags/{exploit_name}"), json=flags)
        if res.status_code != 200:
            print("Could not send flags, am I not authenticated?")
        else:
            flags.clear()
    except ConnectionError:
        print("Could not send flags, I will send them later.")


def main():
    n_workers = os.cpu_count()
    wait_time = 0

    parse_args()
    check_exploit()
    session = authenticate()
    print("Retrieving config...")
    get_config(session)

    try:
        wave = 1
        while True:
            print()
            print(f"[{wave:03d}] Beginning new run...")
            start = time()
            fails = run_exploit_on_teams(n_workers)
            wave_time = time() - start
            print(f"[{wave:03d}] Run finished, got {len(flags)} flags")
            print(f"[{wave:03d}] Exploit failed on {fails} teams")
            print(f"[{wave:03d}] Took {wave_time:.2f} seconds")
            if len(flags) == 0:
                print(f"[{wave:03d}] Got 0 flags, something's broken!")
            send_flags(session)
            sleep(wait_time)
            get_config(session)  # Refresh config
            n_workers, wait_time = compute_parameters(wave_time, wave)
            print(f"[{wave:03d}] New parameters: n_workers = {n_workers}, wait_time = {wait_time:.2f}s")
            wave += 1
    except KeyboardInterrupt:
        print("Ctrl+C detected, exiting...")


if __name__ == "__main__":
    main()
