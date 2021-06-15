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

###################################################################################################
## SETTTINGS ######################################################################################
###################################################################################################

# Original set of latencies
#LATENCIES = ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
#LATENCIES = ["2.0ms"]
LATENCIES = ['15.458ms', '97.73ms'] #['2.684ms', '15.458ms', '97.73ms']  #['15.458ms', '97.73ms']
LOSS_RATES = [0]     #[ 0.1, 0.5, 1, 1.5, 2, 2.5, 3] + list(range(4, 21)):
NUM_PINGS = 10  # for measuring the practical latency
#SPEEDS = [1000, 10]
SPEEDS = [1000, 10]

# xvzcf's experiment used POOL_SIZE = 40
# We start as many servers as clients, so make sure to adjust accordingly
ITERATIONS = 2
POOL_SIZE = 40
START_PORT = 10000
SERVER_PORTS = [str(port) for port in range(10000, 10000+POOL_SIZE)]
MEASUREMENTS_PER_PROCESS = 500
MEASUREMENTS_PER_CLIENT = 500

###################################################################################################


SCRIPTDIR = Path(sys.path[0]).resolve()
sys.path.append(str(SCRIPTDIR.parent.parent / "mk-cert"))


import algorithms

hostname = "servername"

#: UserID of the user so we don't end up with a bunch of root-owned files
USERID = int(os.environ.get("SUDO_UID", 1001))
#: Group ID of the user so we don't end up with a bunch of root-owned files
GROUPID = int(os.environ.get("SUDO_GID", 1001))


class CustomFormatter(logging.Formatter):
    """
    Logging Formatter to add colors and count warning / errors

    https://stackoverflow.com/a/56944256/248065
    """

    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)-8s - %(message)-50s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


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
    #Experiment('sign', "SikeP434Compressed", "Falcon512", "RainbowIClassic", "RainbowIClassic"),
    Experiment('sign', "NtruHps2048509", "Falcon512", "Falcon512", "Falcon512"),
    #  KEMTLS
    Experiment('kemtls', "Kyber512", "Kyber512", "Dilithium2", "Dilithium2"),
    #Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "Gemss128"),
    #Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "Gemss128", "Gemss128"),
    Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "RainbowICircumzenithal"),
    Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "RainbowICircumzenithal", "RainbowICircumzenithal"),
    Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "XMSS", "RainbowIClassic"),
    #Experiment('kemtls', "SikeP434Compressed", "SikeP434Compressed", "RainbowIClassic", "RainbowIClassic"),
    Experiment('kemtls', "NtruHps2048509", "NtruHps2048509", "Falcon512", "Falcon512"),
    #   KEMTLS + CA
    Experiment("kemtls", "Kyber512", "Kyber512", "Dilithium2", "Dilithium2", "Kyber512", "Dilithium2"),
    Experiment("kemtls", "SikeP434Compressed", "SikeP434Compressed", "XMSS", "RainbowIClassic", "SikeP434Compressed", "RainbowIClassic"),
    Experiment("kemtls", "NtruHps2048509", "NtruHps2048509", "Falcon512", "Falcon512", "NtruHps2048509", "Falcon512"),
    Experiment("kemtls", "SikeP434Compressed", "SikeP434Compressed", "RainbowIClassic", "RainbowIClassic", "SikeP434Compressed", "RainbowIClassic"),
    # KEMTLS PDK experiments
    #  TLS with cached certs
    Experiment("sign-cached", "X25519", "RSA2048", "RSA2048"),
    Experiment("sign-cached", "X25519", "RSA2048", "RSA2048", client_auth="RSA2048", client_ca="RSA2048"),
    *(
        Experiment("sign-cached", kex, sig)
        for kex, sig in [
            ("Kyber512", "Dilithium2"),
            #("Lightsaber", "Dilithium2"),
            ("NtruHps2048509", "Falcon512"),
            #("Kyber512", "RainbowIClassic"),
            # Minimal Finalist
            #("NtruHps2048509", "RainbowIClassic"),
            # Minimal
            ("SikeP434Compressed", "RainbowIClassic"),
        ]
    ),
    #  TLS with cached certs + client auth
    *(
        Experiment("sign-cached", kex, sig, client_auth=clauth, client_ca=clca)
        for kex, sig, clauth, clca in [
            ("Kyber512", "Dilithium2", "Dilithium2", "Dilithium2"),
            #("Lightsaber", "Dilithium2", "Dilithium2", "Dilithium2"),
            ("NtruHps2048509", "Falcon512", "Falcon512", "Falcon512"),
            # Minimal Finalist
            #("NtruHps2048509", "RainbowIClassic", "Falcon512", "RainbowIClassic"),
            # Minimal
            ("SikeP434Compressed", "RainbowIClassic", "Falcon512", "RainbowIClassic"),
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
            #"ClassicMcEliece348864",
            #"Hqc128",
            #"NtruPrimeNtrulpr653",
            #"NtruPrimeSntrup653",
            #"BikeL1Fo",
            #"FrodoKem640Shake",

            #"SikeP434",
            # Minimal
            "SikeP434Compressed",
        ]
    ),
    #    With mutual auth
    *(
        Experiment("pdk", kex, kex, client_auth=clauth, client_ca=clca)
        for kex, clauth, clca in [
            ("Kyber512", "Kyber512", "Dilithium2"),
            ("Lightsaber", "Lightsaber", "Dilithium2"),
            ("NtruHps2048509", "NtruHps2048509", "Falcon512"),
            #("Hqc128", "Hqc128", "RainbowIClassic"),
            #("NtruPrimeNtrulpr653", "NtruPrimeNtrulpr653", "Falcon512"),
            #("NtruPrimeSntrup653", "NtruPrimeSntrup653", "Falcon512"),
            #("BikeL1Fo", "BikeL1Fo", "RainbowIClassic"),
            #("FrodoKem640Shake", "FrodoKem640Shake", "SphincsSha256128sSimple"),
            #("SikeP434", "SikeP434", "RainbowIClassic"),
            # Minimal Finalist
            #("NtruHps2048509", "NtruHps2048509", "RainbowIClassic"),
            # Minimal
            ("SikeP434Compressed", "SikeP434Compressed", "RainbowIClassic"),
        ]
    ),
    #   Special combos with McEliece
    *(
        Experiment("pdk", kex, leaf="ClassicMcEliece348864")
        for kex in [
            #"Kyber512",
            #"Lightsaber",
            # Minimal Finalist
            #"NtruHps2048509",
            # Minimal
            "SikeP434Compressed",
        ]
    ),
    # McEliece + Mutual
    Experiment("pdk", "SikeP434Compressed", "ClassicMcEliece348864", client_auth="SikeP434Compressed", client_ca="RainbowIClassic"),
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
    """get unique experiments: one of each type"""
    global ALGORITHMS
    seen = set()
    def update(exp: Experiment) -> Experiment:
        seen.add((exp.type, exp.client_auth is None))
        return exp
    ALGORITHMS = [update(exp) for exp in ALGORITHMS if (exp.type, exp.client_auth is None) not in seen]

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

    logger.debug(" > " + " ".join(command))
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
        logger.debug("Server cmd: %s", ' '.join(cmd))
        self.server_process = subprocess.Popen(
            cmd,
            cwd=self.path,
            stdout=subprocess.PIPE,
            bufsize=8192 * 1024,
        )

        logger.debug(f"Launching server on port {self.port}")
        output_reader = io.TextIOWrapper(self.server_process.stdout, newline="\n")
        measurements = {}
        collected_measurements = []
        while (
            len(collected_measurements) < MEASUREMENTS_PER_PROCESS
            and self.server_process.poll() is None
        ):
            line = output_reader.readline()
            if not line:
                logger.debug("Invalid line from server")
                break

            result = TIMER_REGEX.match(line)
            if result:
                label = result.group("label")
                if label in measurements:
                    logger.error("We're adding the same label '%s' twice to the same measurement", label)
                    logger.error("measurements=%r", measurements)
                    # XXX: this kills the measuring
                    if label == "RECEIVED CLIENT HELLO":
                        logger.warning("Resetting measurement")
                        measurements = {}
                    else:
                        raise ValueError(f"label '{label}' already exisited in measurement")
                measurements[label] = result.group("timing")
                if label == self.last_msg:
                    collected_measurements.append(measurements)
                    measurements = {}
            else:
                logger.warn("Line '%s' did not match regex", line)

        logger.debug("[server] Sending data through pipe")
        self.pipe.send((' '.join(cmd), collected_measurements))
        time.sleep(1)

        logger.debug("Terminating server")
        self.server_process.terminate()
        try:
            self.server_process.wait(5)
        except subprocess.TimeoutExpired:
            logger.exception("Timeout expired while waiting for server on {port} to terminate")
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
        logger.error("Unknown experiment type=%s", type)
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
        logger.debug(f"Starting measurements on port {port}")
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
        logger.debug("Client cmd: %s", ' '.join(cmd))
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
            logger.exception("Sever has hung itself, restarting measurements")
            client_measurements.clear()
            server.terminate()
            server.kill()
            time.sleep(15)
            server.join(5)
            server = ServerProcess(path, port, type, inpipe, cached_int)
            server.start()
            continue

        logger.debug(f"Completed measurements on port {port}")
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

    logger.debug("Joining server")
    server.join(5)

    if not outpipe.poll(10):
        logger.error("No data available from server")
        sys.exit(1)
    (server_cmd, server_data) = outpipe.recv()
    if len(server_data) != len(client_measurements):
        logger.error(f"Process on {port} out of sync {len(server_data)} != {len(client_measurements)}")
        sys.exit(1)

    output_queue.put((' '.join(cmd), server_cmd, list(zip(server_data, client_measurements))))


def experiment_run_timers(experiment: Experiment, cached_int: bool) -> Tuple[str, str, List[Dict[str, Any]]]:
    path = get_experiment_path(experiment)
    tasks = [(port, experiment, cached_int) for port in SERVER_PORTS]
    output_queue = multiprocessing.Queue()
    processes = [
        multiprocessing.Process(target=run_measurement, args=(output_queue, *args))
        for args in tasks
    ]
    results = []
    rpath = path.relative_to(SCRIPTDIR.parent)
    logger.debug(f"Starting processes on {rpath} for {experiment}")
    for process in processes:
        process.start()

    # Consume output
    for _ in range(len(processes)):
        results.append(output_queue.get())

    logger.debug(f"Joining processes on {rpath} for {experiment}")
    for process in processes:
        process.join(5)

    flattened = (results[0][0], results[0][1], [])
    for _, _, measurements in results:
        flattened[2].extend(measurements)

    return flattened


def get_rtt_ms():
    logger.info("Pinging")
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

    logger.debug(" > " + " ".join(command))
    result = run_subprocess(command)

    result_fmt = result.splitlines()[-1].split("/")
    return result_fmt[4]


def write_result(outfile: io.TextIOBase, outlog: io.TextIOBase, results: Tuple[str, str, List[Any]]):
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
    try:
        return socket.gethostbyaddr("10.99.0.1")[0]
    except:
        logger.exception("You probably need to set up '10.99.0.1' in servername in /etc/hosts")
        raise


def get_filename(experiment: Experiment, int_only: bool, rtt_ms, pkt_loss, rate, ext="csv") -> Path:
    fileprefix = f"{experiment.kex}_{experiment.leaf}_{experiment.intermediate}"
    if not int_only:
        fileprefix += f"_{experiment.root}"
    if experiment.client_auth is not None:
        fileprefix += f"_clauth_{experiment.client_auth}_{experiment.client_ca}"
    fileprefix += f"_{rtt_ms}ms"
    caching_type = "int-chain" if not int_only else "int-only"
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
            logger.info("Not regenerating '%s'", expath.name)
            continue
        logger.info("Regenerating '%s'", expath.name)

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
        dirname += f"-clauth-{exp.client_auth}-{exp.client_ca}".lower()
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

        for (experiment, int_only, pkt_loss) in itertools.product(ALGORITHMS, [True, False], LOSS_RATES):
            if latency_ms == LATENCIES[0]:
                rate = 1000
            else:
                rate = 10
            (type, kex_alg, leaf, intermediate, root, client_auth, client_ca) = experiment
            if type in ("pdk", "sign-cached") and not int_only:
                # Skip PDK variants like KKDD, they don't make sense as the cert isn't sent.
                continue
            experiment = get_experiment_instantiation(experiment)
            logger.info(
                f"Experiment for {type} {kex_alg} {leaf} " +
                (f"{intermediate} " if intermediate is not None else "") +
                (f"{root} " if not int_only else "") +
                (f"(client auth: {client_auth} signed by {client_ca}) " if client_auth is not None else "") +
                f"for {rtt_ms}ms latency with "
                f"{'intermediate only' if int_only else 'full cert chain'} "
                f"and {pkt_loss}% loss on {rate}mbit"
            )

            change_qdisc("cli_ns", "cli_ve", pkt_loss, delay=latency_ms, rate=rate)
            change_qdisc("srv_ns", "srv_ve", pkt_loss, delay=latency_ms, rate=rate)
            result = []
            fngetter = partial(get_filename,
                experiment, int_only, rtt_ms, pkt_loss, rate,
            )
            start_time = datetime.datetime.utcnow()
            for _ in range(ITERATIONS):
                result += experiment_run_timers(experiment, int_only)
            duration = datetime.datetime.utcnow() - start_time
            logger.info("took %s", duration)

            with open(fngetter("csv"), "w+") as outresult, open(fngetter("cmdline"), "w+") as outlog:
                write_result(outresult, outlog, result)
            os.chown(fngetter("csv"), uid=USERID, gid=GROUPID)
            os.chown(fngetter("cmdline"), uid=USERID, gid=GROUPID)


if __name__ == "__main__":
    level = getattr(logging, os.environ.get("DEBUG", "INFO"))
    logger = logging.getLogger("BENCHMARKER")
    logger.setLevel(level)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(level)

    ch.setFormatter(CustomFormatter())

    logger.addHandler(ch)

    if (type := os.environ.get("EXPERIMENT")) is not None:
        ALGORITHMS = filter(lambda x: x.type == type, ALGORITHMS)
    if (kex := os.environ.get("KEX")) is not None:
        ALGORITHMS = filter(lambda x: x.kex == kex, ALGORITHMS)
    if (leaf := os.environ.get("LEAF")) is not None:
        ALGORITHMS = filter(lambda x: x.leaf == leaf, ALGORITHMS)
    if (root := os.environ.get("ROOT")) is not None:
        ALGORITHMS = filter(lambda x: x.root == root, ALGORITHMS)
    if (client_auth := os.environ.get("CLIENT_AUTH")) is not None:
        ALGORITHMS = filter(lambda x: x.client_auth == client_auth, ALGORITHMS)
    if (client_ca := os.environ.get("CLIENT_CA")) is not None:
        ALGORITHMS = filter(lambda x: x.client_ca == client_ca, ALGORITHMS)
    ALGORITHMS = list(ALGORITHMS)

    if len(sys.argv) < 2 or sys.argv[1] != "full":
        logger.warning("Running only one experiment of each type")
        only_unique_experiments()

    logger.info("Sign experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "sign")))
    logger.info("KEMTLS experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "kemtls")))
    logger.info("PDK experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "pdk")))
    logger.info("Sign-cached experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "sign-cached")))

    setup_experiments()
    hostname = reverse_resolve_hostname()
    main()
