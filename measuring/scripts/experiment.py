"""Based on https://github.com/xvzcf/pq-tls-benchmark/blob/master/emulation-exp/code/kex/experiment.py"""

import csv
import multiprocessing
import os
import io
import subprocess
import itertools
import time
import re
import socket
import logging
import datetime
from pathlib import Path
from typing import Tuple

hostname = "servername"

ALGORITHMS = (
    # Need to specify leaf always as sigalg to construct correct binary directory
    # EXPERIMENT - KEX - LEAF - INT - ROOT
    ('sign', 'X25519', 'RSA2048', 'RSA2048', 'RSA2048'),
    # KEMTLS paper
    #  PQ Signed KEX
    #('sign', "SikeP434Compressed", "Falcon512", "XMSS", "gemss128"),
    #('sign', "SikeP434Compressed", "Falcon512", "gemss128", "gemss128"),
    ('sign', "SikeP434Compressed", "Falcon512", "XMSS", "RainbowICircumzenithal"),
    ('sign', "SikeP434Compressed", "Falcon512", "RainbowICircumzenithal", "RainbowICircumzenithal"),
    ('sign', "Kyber512", "Dilithium2", "Dilithium2", "Dilithium2"),
    ('sign', "NtruHps2048509", "Falcon512", "Falcon512", "Falcon512"),
    #  KEMTLS
    #('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "gemss128"),
    #('kemtls', "SikeP434Compressed", "SikeP434Compressed", "gemss128", "gemss128"),
    ('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "RainbowICircumzenithal"),
    ('kemtls', "SikeP434Compressed", "SikeP434Compressed", "RainbowICircumzenithal", "RainbowICircumzenithal"),
    ('kemtls', "Kyber512", "Kyber512", "Dilithium2", "Dilithium2"),
    ('kemtls', "NtruHps2048509", "NtruHps2048509", "Falcon512", "Falcon512"),
    # KEMTLS PDK
    ("pdk", "Kyber512", "Kyber512", None, None),
)

# Original set of latencies
# LATENCIES = ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
LATENCIES = ['15.458ms', '97.73ms'] #['2.684ms', '15.458ms', '97.73ms']  #['15.458ms', '97.73ms']
LOSS_RATES = [0]     #[ 0.1, 0.5, 1, 1.5, 2, 2.5, 3] + list(range(4, 21)):
NUM_PINGS = 50  # for measuring the practical latency
SPEEDS = [1000, 10]


# xvzcf's experiment used POOL_SIZE = 40
# We start as many servers as clients, so make sure to adjust accordingly
ITERATIONS = 2
POOL_SIZE = 20
START_PORT = 10000
SERVER_PORTS = [str(port) for port in range(10000, 10000+POOL_SIZE)]
MEASUREMENTS_PER_PROCESS = 50
MEASUREMENTS_PER_CLIENT = 50

TIMER_REGEX = re.compile(r"(?P<label>[A-Z ]+): (?P<timing>\d+) ns")


def run_subprocess(command, working_dir=".", expected_returncode=0):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
        text=True,
        check=False,
    )
    assert result.returncode == expected_returncode, f"Failed to run '{command}'"
    return result.stdout


def change_qdisc(ns, dev, pkt_loss, delay, rate=1000):
    if pkt_loss == 0:
        command = [
            "ip", "netns", "exec", ns, "tc", "qdisc", "change", "dev", dev,
            "root", "netem", "limit", "1000", "delay", delay,
            "rate", f"{rate}mbit",
        ]
    else:
        command = [
            "ip", "netns", "exec", ns, "tc", "qdisc", "change", "dev", dev,
            "root", "netem", "limit", "1000", "loss", "{0}%".format(pkt_loss),
            "delay", delay, "rate", f"{rate}mbit",
        ]

    logging.debug(" > " + " ".join(command))
    run_subprocess(command)


class ServerProcess(multiprocessing.Process):
    def __init__(self, path, port, type, pipe, cached_int=False):
        super().__init__(daemon=False)
        self.path = path
        self.port = port
        self.pipe = pipe
        self.last_msg = "HANDSHAKE COMPLETED"
        self.servername = "tlsserver"
        self.type = type
        if type == "sign" or type == "signcached":
            self.certname = "signing" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "signing.key"
        elif type == "kemtls" or type == "pdk":
            self.certname = "kem" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "kem.key"

    def run(self):
        self.server_process = subprocess.Popen(
            [
                "ip", "netns", "exec", "srv_ns",
                f"./{self.servername}",
                "--certs", self.certname,
                "--key", self.keyname,
                "--port", self.port,
                "http",
            ],
            cwd=self.path,
            stdout=subprocess.PIPE,
            bufsize=8192 * 1024,
        )

        logging.debug(f"Launching server on port {self.port}")
        output_reader = io.TextIOWrapper(self.server_process.stdout, newline="\n")
        measurements = {}
        collected_measurements = []
        while (
            len(collected_measurements) < MEASUREMENTS_PER_PROCESS
            and self.server_process.poll() is None
        ):
            line = output_reader.readline()
            if not line:
                break
            line.rstrip()
            result = TIMER_REGEX.match(line)
            if result:
                label = result.group("label")
                measurements[label] = result.group("timing")
                if label == self.last_msg:
                    collected_measurements.append(measurements)
                    measurements = {}

        self.pipe.send(collected_measurements)
        time.sleep(1)

        self.server_process.terminate()
        try:
            self.server_process.wait(5)
        except subprocess.TimeoutExpired:
            logging.exception("Timeout expired while waiting for server on {port} to terminate")
            self.server_process.kill()


def run_measurement(output_queue, path, port, type, cached_int):
    (inpipe, outpipe) = multiprocessing.Pipe()
    server = ServerProcess(path, port, type, inpipe, cached_int)
    server.start()
    time.sleep(1)

    clientname = "tlsclient"
    LAST_MSG = "HANDSHAKE COMPLETED"
    if type == "sign":
        caname = "signing" + ("-int" if cached_int else "-ca") + ".crt"
    elif type == "kemtls" or type == "pdk":
        caname = "kem" + ("-int" if cached_int else "-ca") + ".crt"

    client_measurements = []
    restarts = 0
    allowed_restarts = 2 * MEASUREMENTS_PER_PROCESS / MEASUREMENTS_PER_CLIENT
    cache_args = []
    if type == "pdk":
        cache_args = ["--cached-certs", "kem.crt"]
    elif type == "signcached":
        if not cached_int:
            cache_args = ["--cached-certs", "signing.all.crt"]
        else:
            cache_args = ["--cached-certs", "signing.chain.crt"]
    while len(client_measurements) < MEASUREMENTS_PER_PROCESS and server.is_alive() and restarts < allowed_restarts:
        logging.debug(f"Starting measurements on port {port}")
        try:
            proc_result = subprocess.run(
                [
                    "ip", "netns", "exec", "cli_ns",
                    f"./{clientname}",
                    "--cafile", caname,
                    "--loops",
                    str(min(MEASUREMENTS_PER_PROCESS - len(client_measurements),
                            MEASUREMENTS_PER_CLIENT)),
                    "--port", port,
                    "--no-tickets",
                    "--http",
                    *cache_args,
                    hostname,
                ],
                text=True,
                stdout=subprocess.PIPE,
                timeout=10 * MEASUREMENTS_PER_CLIENT,
                check=False,
                cwd=path,
            )
        except subprocess.TimeoutExpired:
            logging.exception("Sever has hung itself, restarting measurements")
            client_measurements.clear()
            server.terminate()
            server.kill()
            time.sleep(15)
            server.join(5)
            server = ServerProcess(path, port, type, inpipe, cached_int)
            server.start()
            continue

        logging.debug(f"Completed measurements on port {port}")
        measurement = {}
        for line in proc_result.stdout.split("\n"):
            assert 'WebPKIError' not in line
            result = TIMER_REGEX.match(line)
            if result:
                label = result.group("label")
                measurement[label] = result.group("timing")
                if label == LAST_MSG:
                    client_measurements.append(measurement)
                    measurement = {}
        restarts += 1

    server.join(5)

    server_data = outpipe.recv()
    assert len(server_data) == len(
        client_measurements
    ), f"[!] Process on {port} out of sync {len(server_data)} != {len(client_measurements)}"

    output_queue.put(list(zip(server_data, client_measurements)))


def experiment_run_timers(path, type, cached_int):
    tasks = [(path, port, type, cached_int) for port in SERVER_PORTS]
    output_queue = multiprocessing.Queue()
    processes = [
        multiprocessing.Process(target=run_measurement, args=(output_queue, *args))
        for args in tasks
    ]
    results = []
    logging.debug(f"Starting processes on {path} for {type}")
    for process in processes:
        process.start()

    # Consume output
    for _ in range(len(processes)):
        results.extend(output_queue.get())

    logging.debug(f"Joining processes on {path} for {type}")
    for process in processes:
        process.join(5)

    return results


def get_rtt_ms():
    logging.info("Pinging")
    command = [
        "ip",
        "netns",
        "exec",
        "cli_ns",
        "ping",
        hostname,
        "-c",
        str(NUM_PINGS),
    ]

    logging.debug(" > " + " ".join(command))
    result = run_subprocess(command)

    result_fmt = result.splitlines()[-1].split("/")
    return result_fmt[4]


def write_result(outfile, results):
    server_keys = results[0][0].keys()
    client_keys = results[0][1].keys()
    keys = [f"client {key.lower()}" for key in client_keys] + [
        f"server {key.lower()}" for key in server_keys
    ]

    writer = csv.DictWriter(outfile, keys)
    writer.writeheader()
    for (server_result, client_result) in results:
        row = {f"client {key.lower()}": value for (key, value) in client_result.items()}
        row.update(
            {f"server {key.lower()}": value for (key, value) in server_result.items()}
        )
        writer.writerow(row)


def reverse_resolve_hostname():
    return socket.gethostbyaddr("10.99.0.1")[0]


def get_filename(kex_alg, leaf, intermediate, root, type, cached_int, rtt_ms, pkt_loss, rate) -> str:
    fileprefix = f"{kex_alg}_{leaf}_{intermediate}"
    if not cached_int:
        fileprefix += f"_{root}"
    fileprefix += f"_{rtt_ms}ms"
    caching_type = "int-chain" if not cached_int else "int-only"
    filename = f"data/{type}-{caching_type}/{fileprefix}_{pkt_loss}_{rate}mbit.csv"
    return filename


def setup_experiments():
    # get unique combinations
    combinations = set(
        get_experiment_instantiation(kex_alg, leaf, inter, root) 
        for (_, kex_alg, leaf, inter, root) in ALGORITHMS
    )

    for (kex, leaf, inter, root) in combinations:
        expath = get_experiment_path(kex, leaf, inter, root)
        if expath.exists():
            logging.warning("Not regenerating '%s'", expath)
            continue
        subprocess.run(
            ["./scripts/create-experimental-setup.sh", kex, leaf, inter, root],
            check=True,
            capture_output=False,
        )


def get_experiment_instantiation(kex_alg: str, leaf: str, intermediate: str, root: str) -> Tuple[str, str, str, str]:
        # intermediate and root might be None, which means we'll need to match
    for (_, kex_, leaf_, intermediate_, root_) in ALGORITHMS:
        if kex_alg != kex_ or leaf != leaf_:
            continue
        if intermediate is None and intermediate_ is not None and root is not None and root == root_:
            intermediate = intermediate_
            break
        elif intermediate is None and root is None:
            if intermediate_ is not None and root_ is not None:
                intermediate = intermediate_
                root = root_
                break
    intermediate = intermediate or "Dilithium2"
    root = root or "Dilithium2"

    return (kex_alg, leaf, intermediate, root)


def get_experiment_path(kex_alg: str, leaf: str, intermediate: str, root: str) -> Path:
    return Path("bin") / f"{kex_alg}-{leaf}-{intermediate}-{root}".lower()


def main():
    os.makedirs("data", exist_ok=True)
    os.chown("data", uid=1001, gid=1001)
    for (type, caching) in itertools.product(["kemtls", "sign", "sign-cached", "pdk"], ["int-chain", "int-only"]):
        dirname = os.path.join("data", f"{type}-{caching}")
        os.makedirs(dirname, exist_ok=True)
        os.chown(dirname, uid=1001, gid=1001)

    for latency_ms in LATENCIES:
        # To get actual (emulated) RTT
        change_qdisc("cli_ns", "cli_ve", 0, delay=latency_ms)
        change_qdisc("srv_ns", "srv_ve", 0, delay=latency_ms)
        rtt_ms = get_rtt_ms()

        for ((type, kex_alg, leaf, intermediate, root), cached_int, pkt_loss, rate) in itertools.product(ALGORITHMS, [True, False], LOSS_RATES, SPEEDS):
            (kex_alg, leaf, intermediate, root) = get_experiment_instantiation(kex_alg, leaf, intermediate, root)
            logging.info(
                f"Experiment for {type} {kex_alg} {leaf} {intermediate} "
                f"{root} for {rtt_ms}ms latency with "
                f"{'cached intermediate' if cached_int else 'full cert chain'} "
                f"and {pkt_loss}% loss on {rate}mbit"
            )

            experiment_path = get_experiment_path(kex_alg, leaf, intermediate, root)

            change_qdisc("cli_ns", "cli_ve", pkt_loss, delay=latency_ms, rate=rate)
            change_qdisc("srv_ns", "srv_ve", pkt_loss, delay=latency_ms, rate=rate)
            result = []
            filename = get_filename(
                kex_alg, leaf, intermediate, root, type, cached_int, rtt_ms, pkt_loss, rate
            )
            start_time = datetime.datetime.utcnow()
            for _ in range(ITERATIONS):
                result += experiment_run_timers(experiment_path, type, cached_int)
            duration = datetime.datetime.utcnow() - start_time
            logging.info("took %s", duration)

            with open(filename, "w+") as out:
                write_result(out, result)
            os.chown(filename, uid=1001, gid=1001)


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S', level=logging.INFO)
    setup_experiments()
    hostname = reverse_resolve_hostname()
    main()
