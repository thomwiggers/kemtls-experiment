"""Based on https://github.com/xvzcf/pq-tls-benchmark/blob/master/emulation-exp/code/kex/experiment.py"""

import csv
from functools import partial
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
from typing import Any, Dict, List, NamedTuple, Optional, Tuple, Union, Literal
import sys

SCRIPTDIR = Path(sys.path[0]).resolve()
sys.path.append(str(SCRIPTDIR.parent.parent / "mk-cert"))


import algorithms

hostname = "servername"

#: UserID of the user so we don't end up with a bunch of root-owned files
USERID = int(os.environ.get("SUDO_UID", 1001))
#: Group ID of the user so we don't end up with a bunch of root-owned files
GROUPID = int(os.environ.get("SUDO_GID", 1001))


class Experiment(NamedTuple):
    """Represents an experiment"""
    type: Union[Literal["sign"], Literal["pdk"], Literal["kemtls"], Literal["sign-cached"]]
    kex: str
    leaf: str
    intermediate: Optional[str] = None
    root: Optional[str] = None
    client_auth: Optional[str] = None
    client_ca: Optional[str] = None


ALGORITHMS = [
    # Need to specify leaf always as sigalg to construct correct binary directory
    # EXPERIMENT - KEX - LEAF - INT - ROOT - CLIENT AUTH - CLIENT CA
    Experiment('sign', 'X25519', 'RSA2048', 'RSA2048', 'RSA2048'),
    Experiment('sign', 'X25519', 'RSA2048', 'RSA2048', 'RSA2048', "RSA2048", "RSA2048"),
    # KEMTLS paper
    #  PQ Signed KEX
    Experiment('sign', "Kyber512", "Dilithium2", "Dilithium2", "Dilithium2"),
    #Experiment('sign', "SikeP434Compressed", "Falcon512", "XMSS", "Gemss128"),
    #Experiment('sign', "SikeP434Compressed", "Falcon512", "Gemss128", "Gemss128"),
    Experiment('sign', "SikeP434Compressed", "Falcon512", "XMSS", "RainbowICircumzenithal"),
    Experiment('sign', "SikeP434Compressed", "Falcon512", "RainbowICircumzenithal", "RainbowICircumzenithal"),
    Experiment('sign', "NtruHps2048509", "Falcon512", "Falcon512", "Falcon512"),
    #  KEMTLS
    Experiment('kemtls', "Kyber512", "Kyber512", "Dilithium2", "Dilithium2"),
    #Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "Gemss128"),
    #Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "Gemss128", "Gemss128"),
    Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "RainbowICircumzenithal"),
    Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "RainbowICircumzenithal", "RainbowICircumzenithal"),
    Experiment('kemtls', "NtruHps2048509", "NtruHps2048509", "Falcon512", "Falcon512"),
    # KEMTLS PDK experiments
    #  TLS with cached certs
    Experiment("sign-cached", "X25519", "RSA2048", "RSA2048", "RSA2048"),
    *(
        Experiment("sign-cached", kex, sig)
        for kex, sig in [
            ("Kyber512", "Dilithium2"),
            ("Lightsaber", "Dilithium2"),
            ("NtruHps2048509", "Falcon512"),
            ("Kyber512", "RainbowIClassic"),
        ]
    ),
    #  PDK
    #   Level 1
    *(
        Experiment("pdk", kex, kex)
        for kex in [
            "Kyber512",
            "Lightsaber",
            "NtruHps2048509",
            "ClassicMcEliece348864",
            "Hqc128",
            "NtruPrimeNtrulpr653",
            "NtruPrimeSntrup653",
            "BikeL1Fo",
            "FrodoKem640Shake",
            "SikeP434",
            "SikeP434Compressed",
        ]
    ),
    #   Special combos with McEliece
    *(
        Experiment("pdk", "ClassicMcEliece348864", kex)
        for kex in [
            "Kyber512",
            "Lightsaber",
            "NtruHps2048509",
            "SikeP434",
            "SikeP434Compressed",
        ]
    ),
]

# Validate choices
def __validate_experiments() -> None:
    known_kems = [kem[1] for kem in algorithms.kems] + ["X25519"]
    known_sigs = [sig[1] for sig in algorithms.signs] + ["RSA2048"]
    for (_, kex, leaf, int, root, client_auth, client_ca) in ALGORITHMS:
        assert kex in known_kems, f"{kex} is not a known KEM"
        assert leaf in known_kems or leaf in known_sigs, f"{leaf} is not a known algorithm"
        assert int is None or int in known_sigs, f"{int} is not a known signature algorithm"
        assert root is None or root in known_sigs, f"{root} is not a known signature algorithm"
        assert client_auth is None or client_auth in known_sigs or client_auth in known_kems, \
            f"{client_auth} is not a known signature algorith or KEM"
        assert client_ca is None or client_ca in known_sigs, f"{client_ca} is not a known sigalg"
__validate_experiments()

def only_unique_experiments() -> None:
    """get unique experiments"""
    global ALGORITHMS
    seen = set()
    def update(exp: Experiment) -> Experiment:
        seen.add(exp.type)
        return exp
    ALGORITHMS = [update(exp) for exp in ALGORITHMS if exp.type not in seen]

# Original set of latencies
# LATENCIES = ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
LATENCIES = ["2.0ms"]
#LATENCIES = ['15.458ms', '97.73ms'] #['2.684ms', '15.458ms', '97.73ms']  #['15.458ms', '97.73ms']
LOSS_RATES = [0]     #[ 0.1, 0.5, 1, 1.5, 2, 2.5, 3] + list(range(4, 21)):
NUM_PINGS = 5  # for measuring the practical latency
#SPEEDS = [1000, 10]
SPEEDS = [1000]


# xvzcf's experiment used POOL_SIZE = 40
# We start as many servers as clients, so make sure to adjust accordingly
ITERATIONS = 1
POOL_SIZE = 1
START_PORT = 10000
SERVER_PORTS = [str(port) for port in range(10000, 10000+POOL_SIZE)]
MEASUREMENTS_PER_PROCESS = 5
MEASUREMENTS_PER_CLIENT = 5

TIMER_REGEX = re.compile(r"(?P<label>[A-Z ]+): (?P<timing>\d+) ns")


def run_subprocess(command, working_dir=".", expected_returncode=0) -> str:
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
        text=True,
        check=False,
    )
    assert result.returncode == expected_returncode, f"Failed to run '{command}':\n{result.stdout}"
    return result.stdout


def change_qdisc(ns, dev, pkt_loss, delay, rate=1000) -> None:
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
    def __init__(self, port, pipe, experiment: Experiment, cached_int=False):
        super().__init__(daemon=False)
        self.experiment = experiment
        self.path = get_experiment_path(experiment)
        self.port = port
        self.pipe = pipe
        self.last_msg = "HANDSHAKE COMPLETED"
        self.servername = "tlsserver"
        self.type = experiment.type
        self.clientauthopts = []
        type = experiment.type
        if type == "sign" or type == "sign-cached":
            self.certname = "signing" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "signing.key"
        elif type == "kemtls" or type == "pdk":
            self.certname = "kem" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "kem.key"
        else:
            raise ValueError(f"Invalid Experiment type in {experiment}")

        if experiment.client_auth is not None:
            self.clientauthopts = ["--require-auth", "--auth", "client-ca.crt"]

    def run(self):
        cmd = [
            "ip", "netns", "exec", "srv_ns",
            f"./{self.servername}",
            "--certs", self.certname,
            "--key", self.keyname,
            "--port", self.port,
            *self.clientauthopts,
            "http",
        ]
        logging.debug("Server cmd: %s", ' '.join(cmd))
        self.server_process = subprocess.Popen(
            cmd,
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
                logging.debug("Invalid line from server")
                break
    
            result = TIMER_REGEX.match(line)
            if result:
                label = result.group("label")
                if label in measurements:
                    logging.error("We're adding the same label twice to the same measurement")
                    logging.error("measurements=%r", measurements)
                    raise ValueError("label already exisited in measurement")
                measurements[label] = result.group("timing")
                if label == self.last_msg:
                    collected_measurements.append(measurements)
                    measurements = {}
            else:
                logging.warn("Line '%s' did not match regex", line)

        logging.debug("[server] Sending data through pipe")
        self.pipe.send((' '.join(cmd), collected_measurements))
        time.sleep(1)

        logging.debug("Terminating server")
        self.server_process.terminate()
        try:
            self.server_process.wait(5)
        except subprocess.TimeoutExpired:
            logging.exception("Timeout expired while waiting for server on {port} to terminate")
            self.server_process.kill()


def run_measurement(output_queue, port, experiment: Experiment, cached_int):
    (inpipe, outpipe) = multiprocessing.Pipe()
    server = ServerProcess(port, inpipe, experiment, cached_int)
    server.start()
    time.sleep(1)

    path = get_experiment_path(experiment)
    clientname = "tlsclient"
    LAST_MSG = "RECEIVED SERVER REPLY"
    type = experiment.type
    if type == "sign" or type == "sign-cached":
        caname = "signing" + ("-int" if cached_int else "-ca") + ".crt"
    elif type == "kemtls" or type == "pdk":
        caname = "kem" + ("-int" if cached_int else "-ca") + ".crt"
    else:
        logging.error("Unknown experiment type=%s", type)
        sys.exit(1)

    client_measurements = []
    restarts = 0
    allowed_restarts = 2 * MEASUREMENTS_PER_PROCESS / MEASUREMENTS_PER_CLIENT
    cache_args = []
    if type == "pdk":
        cache_args = ["--cached-certs", "kem.crt"]
    elif type == "sign-cached":
        if not cached_int:
            cache_args = ["--cached-certs", "signing.all.crt"]
        else:
            cache_args = ["--cached-certs", "signing.chain.crt"]
    clientauthopts = []
    if experiment.client_auth is not None:
        clientauthopts = ["--auth-certs", "client.crt", "--auth-key", "client.key"]
    while len(client_measurements) < MEASUREMENTS_PER_PROCESS and server.is_alive() and restarts < allowed_restarts:
        logging.debug(f"Starting measurements on port {port}")
        cmd = [
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
            *clientauthopts,
            hostname,
        ]
        logging.debug("Client cmd: %s", ' '.join(cmd))
        try:
            proc_result = subprocess.run(
                cmd,
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

    logging.debug("Joining server")
    server.join(5)

    if not outpipe.poll(10):
        logging.error("No data available from server")
        sys.exit(1)
    (server_cmd, server_data) = outpipe.recv()
    if len(server_data) != len(client_measurements):
        logging.error(f"Process on {port} out of sync {len(server_data)} != {len(client_measurements)}")
        sys.exit(1)

    output_queue.put((' '.join(cmd), server_cmd, list(zip(server_data, client_measurements))))


def experiment_run_timers(experiment: Experiment, cached_int) -> Tuple[str, str, List[Dict[str, Any]]]:
    path = get_experiment_path(experiment)
    tasks = [(port, experiment, cached_int) for port in SERVER_PORTS]
    output_queue = multiprocessing.Queue()
    processes = [
        multiprocessing.Process(target=run_measurement, args=(output_queue, *args))
        for args in tasks
    ]
    results = []
    logging.debug(f"Starting processes on {path} for {experiment}")
    for process in processes:
        process.start()

    # Consume output
    for _ in range(len(processes)):
        results.append(output_queue.get())

    logging.debug(f"Joining processes on {path} for {experiment}")
    for process in processes:
        process.join(5)

    flattened = (results[0][0], results[0][1], [])
    for _, _, measurements in results:
        flattened[2].extend(measurements)

    return flattened


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


def write_result(outfile, outlog, results):
    client_cmd = results[0]
    server_cmd = results[1]
    server_keys = results[2][0][0].keys()
    client_keys = results[2][0][1].keys()
    keys = [f"client {key.lower()}" for key in client_keys] + [
        f"server {key.lower()}" for key in server_keys
    ]

    writer = csv.DictWriter(outfile, keys)
    writer.writeheader()
    for (server_result, client_result) in results[2]:
        row = {f"client {key.lower()}": value for (key, value) in client_result.items()}
        row.update(
            {f"server {key.lower()}": value for (key, value) in server_result.items()}
        )
        writer.writerow(row)

    outlog.write(f"client: {client_cmd}\n")
    outlog.write(f"server: {server_cmd}\n")



def reverse_resolve_hostname() -> str:
    return socket.gethostbyaddr("10.99.0.1")[0]


def get_filename(experiment: Experiment, cached_int, rtt_ms, pkt_loss, rate, ext="csv") -> Path:
    fileprefix = f"{experiment.kex}_{experiment.leaf}_{experiment.intermediate}"
    if not cached_int:
        fileprefix += f"_{experiment.root}"
    fileprefix += f"_{rtt_ms}ms"
    caching_type = "int-chain" if not cached_int else "int-only"
    filename = SCRIPTDIR.parent / "data" / f"{experiment.type}-{caching_type}" / f"{fileprefix}_{pkt_loss}_{rate}mbit.{ext}"
    return filename


def setup_experiments() -> None:
    # get unique combinations
    combinations = set(
        get_experiment_instantiation(experiment) 
        for experiment in ALGORITHMS
    )

    for experiment in combinations:
        expath = get_experiment_path(experiment)
        if expath.exists():
            logging.warning("Not regenerating '%s'", expath)
            continue
        
        subprocess.run(
            [
                SCRIPTDIR / "create-experimental-setup.sh", 
                experiment.kex,
                experiment.leaf,
                experiment.intermediate or "ERROR", 
                experiment.root or "ERROR",
                experiment.client_auth or '',
                experiment.client_ca or '',
            ],
            check=True,
            capture_output=False,
        )


def get_experiment_instantiation(experiment: Experiment) -> Experiment:
    # intermediate and root might be None, which means we'll need to match
    no_client_auth = experiment.client_auth is None
    for combo in ALGORITHMS:
        if all(map(lambda ab: ab[1] is None or ab[0] == ab[1], zip(combo[1:], experiment[1:]))):
            for (field, b) in enumerate(experiment._asdict().items()):
                if b is None:
                    setattr(experiment, field, getattr(combo, field))
            break

    experiment = experiment._replace(
        intermediate=experiment.intermediate or "Dilithium2",
        root=experiment.root or "Dilithium2"
    )

    if no_client_auth:
        experiment = experiment._replace(
            client_auth=None,
            client_ca=None,
        )

    return experiment


def get_experiment_path(exp: Experiment) -> Path:
    kex_alg = exp.kex
    leaf = exp.leaf
    intermediate = exp.intermediate
    root = exp.root
    dirname = f"{kex_alg}-{leaf}-{intermediate}-{root}".lower()
    if exp.client_auth is not None:
        dirname += f"-{exp.client_auth}-{exp.client_ca}".lower()
    return SCRIPTDIR.parent / Path("bin") / dirname


def main():
    os.makedirs("data", exist_ok=True)
    os.chown("data", uid=USERID, gid=GROUPID)
    for (type, caching) in itertools.product(["kemtls", "sign", "sign-cached", "pdk"], ["int-chain", "int-only"]):
        dirname = SCRIPTDIR.parent / "data" / f"{type}-{caching}"
        os.makedirs(dirname, exist_ok=True)
        os.chown(dirname, uid=1001, gid=1001)

    for latency_ms in LATENCIES:
        # To get actual (emulated) RTT
        change_qdisc("cli_ns", "cli_ve", 0, delay=latency_ms)
        change_qdisc("srv_ns", "srv_ve", 0, delay=latency_ms)
        rtt_ms = get_rtt_ms()

        for (experiment, cached_int, pkt_loss, rate) in itertools.product(ALGORITHMS, [True, False], LOSS_RATES, SPEEDS):
            (type, kex_alg, leaf, intermediate, root, client_auth, client_ca) = experiment
            experiment = get_experiment_instantiation(experiment)
            logging.info(
                f"Experiment for {type} {kex_alg} {leaf} {intermediate} "
                f"{root} " + 
                (f"(client auth: {client_auth} signed by {client_ca})" if client_auth is not None else "") +
                f"for {rtt_ms}ms latency with "
                f"{'cached intermediate' if cached_int else 'full cert chain'} "
                f"and {pkt_loss}% loss on {rate}mbit"
            )

            change_qdisc("cli_ns", "cli_ve", pkt_loss, delay=latency_ms, rate=rate)
            change_qdisc("srv_ns", "srv_ve", pkt_loss, delay=latency_ms, rate=rate)
            result = []
            fngetter = partial(get_filename,
                experiment, cached_int, rtt_ms, pkt_loss, rate,
            )
            start_time = datetime.datetime.utcnow()
            for _ in range(ITERATIONS):
                result += experiment_run_timers(experiment, cached_int)
            duration = datetime.datetime.utcnow() - start_time
            logging.info("took %s", duration)

            with open(fngetter("csv"), "w+") as outresult, open(fngetter("cmdline"), "w+") as outlog:
                write_result(outresult, outlog, result)
            os.chown(fngetter("csv"), uid=USERID, gid=GROUPID)
            os.chown(fngetter("cmdline"), uid=USERID, gid=GROUPID)


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%Y/%m/%d %H:%M:%S', level=logging.DEBUG)
    logging.info("Sign experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "sign")))
    logging.info("KEMTLS experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "kemtls")))
    logging.info("PDK experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "pdk")))
    logging.info("Sign-cached experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "sign-cached")))

    only_unique_experiments()
    
    setup_experiments()
    hostname = reverse_resolve_hostname()
    main()