"""Based on https://github.com/xvzcf/pq-tls-benchmark/blob/master/emulation-exp/code/kex/experiment.py"""

import csv
from dataclasses import dataclass
from functools import partial
import multiprocessing
from multiprocessing.connection import Connection
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
from typing import (
    Final,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
    Literal,
    cast,
)
import sys

###################################################################################################
## SETTTINGS ######################################################################################
###################################################################################################

# Original set of latencies
# LATENCIES = ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
# LATENCIES = ["2.0ms"]
LATENCIES: Final[list[str]] = [
    "15.458ms",
    "97.73ms",
]  # ['2.684ms', '15.458ms', '97.73ms']  #['15.458ms', '97.73ms']
LOSS_RATES: Final[list[int]] = [
    0
]  # [ 0.1, 0.5, 1, 1.5, 2, 2.5, 3] + list(range(4, 21)):
NUM_PINGS: Final[int] = 10  # for measuring the practical latency
# SPEEDS = [1000, 10]
SPEEDS: Final[list[int]] = [1000, 10]

# xvzcf's experiment used POOL_SIZE = 40
# We start as many servers as clients, so make sure to adjust accordingly
START_PORT: Final[int] = 10000
POOL_SIZE: Final[int] = 1
ITERATIONS: Final[int] = 1
# Total iterations = ITERATIONS * POOL_SIZE * MEASUREMENTS_PER_ITERATION
MEASUREMENTS_PER_ITERATION: Final[int] = 20
MEASUREMENTS_PER_CLIENT: Final[int] = 20

###################################################################################################

ResultType = dict[str, str]
ResultListType = list[ResultType]

SCRIPTDIR: Path = Path(sys.path[0]).resolve()
sys.path.append(str(SCRIPTDIR.parent.parent / "mk-cert"))

SERVER_PORTS: Final[list[str]] = [
    str(port) for port in range(START_PORT, START_PORT + POOL_SIZE)
]


import algorithms

hostname = "servername"

#: UserID of the user so we don't end up with a bunch of root-owned files
USERID: int = int(os.environ.get("SUDO_UID", 1001))
#: Group ID of the user so we don't end up with a bunch of root-owned files
GROUPID: int = int(os.environ.get("SUDO_GID", 1001))


class CustomFormatter(logging.Formatter):
    """
    Logging Formatter to add colors and count warning / errors

    https://stackoverflow.com/a/56944256/248065
    """

    grey: Final[str] = "\x1b[38;21m"
    yellow: Final[str] = "\x1b[33;21m"
    red: Final[str] = "\x1b[31;21m"
    bold_red: Final[str] = "\x1b[31;1m"
    reset: Final[str] = "\x1b[0m"
    format_tpl: Final[
        str
    ] = "%(asctime)s - %(levelname)-8s - %(message)-50s (%(filename)s:%(lineno)d)"

    FORMATS: Final[dict[int, str]] = {
        logging.DEBUG: grey + format_tpl + reset,
        logging.INFO: grey + format_tpl + reset,
        logging.WARNING: yellow + format_tpl + reset,
        logging.ERROR: red + format_tpl + reset,
        logging.CRITICAL: bold_red + format_tpl + reset,
    }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


ExperimentType = Union[
    Literal["sign"],
    Literal["pdk"],
    Literal["kemtls"],
    Literal["sign-cached"],
    Literal["optls"],
]


class Experiment(NamedTuple):
    """Represents an experiment"""

    type: ExperimentType
    kex: str
    leaf: str
    intermediate: Optional[str] = None
    root: Optional[str] = None
    client_auth: Optional[str] = None
    client_ca: Optional[str] = None
    keygen_cache: bool = False


FRODOS = [
    f"FrodoKem{size.title()}{alg.title()}"
    for size in ("640", "976", "1344")
    for alg in ("aes", "shake")
]
SMALLFRODOS = [frodo for frodo in FRODOS if "640" in frodo]
KYBERS = ["Kyber512", "Kyber768", "Kyber1024"]
BIKES = ["BikeL1", "BikeL3"]  # NOTE: IND-CPA!
HQCS = ["Hqc128", "Hqc192", "Hqc256"]
MCELIECES_ = [
    f"ClassicMcEliece{size}{variant}"
    for size in ("348864", "460896", "6688128", "6960119", "8192128")
    for variant in ["", "f"]
]
MCELIECEL1 = [mc for mc in MCELIECES_ if "348864" in mc]
MCELIECEL3 = [mc for mc in MCELIECES_ if "460896" in mc]
MCELIECEL5 = [mc for mc in MCELIECES_ if mc not in (MCELIECEL1 + MCELIECEL3)]
MCELIECES = {1: MCELIECEL1, 3: MCELIECEL3, 5: MCELIECEL5}

DILITHIUMS = ["Dilithium2", "Dilithium3", "Dilithium5"]
FALCONS = ["Falcon512", "Falcon1024"]
SPHINCSES_ = [
    f"SphincsShake{size}{var}Simple" for size in [128, 192, 256] for var in ["s", "f"]
]
SPHINCSESL1 = [spx for spx in SPHINCSES_ if "128" in spx]
SPHINCSESL3 = [spx for spx in SPHINCSES_ if "196" in spx]
SPHINCSESL5 = [spx for spx in SPHINCSES_ if "256" in spx]

UOVS_ = [
    f"Pqov{size}{variant}"
    for size in ("1616064", "25611244", "25618472", "25624496")
    for variant in ["Classic"]
]
UOVL1 = [uov for uov in UOVS_ if "1616064" in uov or "25611244" in uov]
UOVL3 = [uov for uov in UOVS_ if "25618472" in uov]
UOVL5 = [uov for uov in UOVS_ if "25624496" in uov]
UOVS = {1: UOVL1, 3: UOVL3, 5: UOVL5}

# KEMS: list[str] = [
#     *KYBERS,
#     *HQCS,
#     *BIKES,
#     *SMALLFRODOS,
# ]

KEMSL1 = [KYBERS[0], BIKES[0], HQCS[0], *SMALLFRODOS]
KEMSL3 = [KYBERS[1], BIKES[1], HQCS[1]]
KEMSL5 = [KYBERS[2], HQCS[2]]

LEVELS = [1, 3, 5]
KEMS = {1: KEMSL1, 3: KEMSL3, 5: KEMSL5}

# SIGS: list[str] = [*DILITHIUMS, *FALCONS, *SPHINCSES]

SIGSL1 = [DILITHIUMS[0], FALCONS[0], *SPHINCSESL1]
SIGSL3 = [DILITHIUMS[1], FALCONS[1], *SPHINCSESL3]
SIGSL5 = [DILITHIUMS[2], FALCONS[1], *SPHINCSESL5]

SIGS = {1: SIGSL1, 3: SIGSL3, 5: SIGSL5}

ALGORITHMS: list[Experiment] = [
    # Need to specify leaf always as sigalg to construct correct binary directory
    # EXPERIMENT - KEX - LEAF - INT - ROOT - CLIENT AUTH - CLIENT CA
    Experiment("sign", "X25519", "RSA2048", "RSA2048", "RSA2048"),
    Experiment("sign", "X25519", "RSA2048", "RSA2048", "RSA2048"),
    Experiment("sign", "X25519", "RSA2048", "RSA2048", "RSA2048", "RSA2048", "RSA2048"),
    # KEMTLS paper
    #  PQ Signed KEX
    *(Experiment("sign", kem, sig, sig, sig) for kem in KEMSL1 for sig in SIGSL1),
    *(Experiment("sign", kem, sig, sig, sig) for kem in KEMSL3 for sig in SIGSL3),
    *(Experiment("sign", kem, sig, sig, sig) for kem in KEMSL5 for sig in SIGSL5),
    ## Mutually authenticated
    *(
        Experiment("sign", kem, sig, sig, sig, sig, sig)
        for kem in KEMSL1
        for sig in SIGSL1
    ),
    *(
        Experiment("sign", kem, sig, sig, sig, sig, sig)
        for kem in KEMSL3
        for sig in SIGSL3
    ),
    *(
        Experiment("sign", kem, sig, sig, sig, sig, sig)
        for kem in KEMSL5
        for sig in SIGSL5
    ),
    #  TLS with cached certs + client auth
    *(
        Experiment("sign-cached", kex, sig, client_auth=sig, client_ca=sig)
        for level in LEVELS
        for kex in KEMS[level]
        for sig in SIGS[level]
    ),
    #  KEMTLS
    *(
        Experiment("kemtls", kex, kex, sig, sig)
        for level in LEVELS
        for kex in KEMS[level]
        for sig in SIGS[level]
    ),
    #  KEMTLS mutual
    *(
        Experiment("kemtls", kex, kex, sig, sig, kex, sig)
        for level in LEVELS
        for kex in KEMS[level]
        for sig in SIGS[level]
    ),
    #  KEMTLS extra combinations L1
    *(
        Experiment("kemtls", kex, kex, sig, sig2)
        for kex in KEMSL1
        for sig in [DILITHIUMS[0], FALCONS[0]]
        for sig2 in [FALCONS[0], *UOVS[1]]
        if sig2 != sig
    ),
    #  KEMTLS extra L3
    *(
        Experiment("kemtls", kex, kex, sig, sig2)
        for kex in KEMSL3
        for sig in [DILITHIUMS[1], FALCONS[1]]
        for sig2 in [FALCONS[1], *UOVS[3]]
        if sig2 != sig
    ),
    #  KEMTLS extra L5
    *(
        Experiment("kemtls", kex, kex, sig, sig2)
        for kex in KEMSL5
        for sig in [DILITHIUMS[2], FALCONS[1]]
        for sig2 in [FALCONS[1], *UOVS[5]]
        if sig2 != sig
    ),
    #  KEMTLS MUTUAL extra combinations
    *(
        Experiment("kemtls", kex, kex, sig, sig2, kex, sig2)
        for kex in KEMSL1
        for sig in [DILITHIUMS[0], FALCONS[0]]
        for sig2 in [DILITHIUMS[0], FALCONS[0], *UOVS[1]]
    ),
    #  KEMTLS MUTUAL extra combinations
    *(
        Experiment("kemtls", kex, kex, sig, sig2, kex, sig2)
        for kex in KEMSL3
        for sig in [DILITHIUMS[1], FALCONS[1]]
        for sig2 in [DILITHIUMS[1], FALCONS[1], *UOVS[3]]
        if sig2 != sig
    ),
    *(
        Experiment("kemtls", kex, kex, sig, sig2, kex, sig2)
        for kex in KEMSL5
        for sig in [DILITHIUMS[2], FALCONS[1]]
        for sig2 in [DILITHIUMS[2], FALCONS[1], *UOVS[5]]
        if sig2 != sig
    ),
    #  PDK
    #   Level 1
    *(Experiment("pdk", kex, kex) for kex in [*KEMSL1, *KEMSL3, *KEMSL5]),
    #    With mutual auth
    *(
        Experiment("pdk", kex, kex, client_auth=kex, client_ca=sig)
        for level in LEVELS
        for kex in KEMS[level]
        for sig in SIGS[level]
    ),
    #   Special combos with McEliece
    *(
        Experiment("pdk", kex, leaf=mceliece)
        for level in LEVELS
        for kex in KEMS[level]
        for mceliece in MCELIECES[level]
    ),
    # McEliece + Mutual
    *(
        Experiment("pdk", kex, mceliece, client_auth=kex, client_ca=sig)
        for level in LEVELS
        for kex in KEMS[level]
        for sig in SIGS[level]
        for mceliece in MCELIECES[level]
    ),
    # OPTLS
    *(
        Experiment("optls", alg, alg, "Falcon512", "Falcon512", keygen_cache=True)
        for alg in (
            "CSIDH2047K221",
            "CTIDH2047K221",
        )
    ),
    *(
        Experiment("optls", alg, alg, "Falcon512", "Falcon512", keygen_cache=False)
        for alg in (
            "CSIDH2047K221",
            "CTIDH2047K221",
        )
    ),
]

# Validate choices
def __validate_experiments() -> None:
    nikes: list[str] = [alg.upper() for alg in algorithms.nikes]
    known_kexes: list[str] = [kem[1] for kem in algorithms.kems] + ["X25519"] + nikes
    known_sigs: list[str] = [sig[1] for sig in algorithms.signs] + ["RSA2048"]
    for (_, kex, leaf, int, root, client_auth, client_ca, _) in ALGORITHMS:
        assert (
            kex in known_kexes
        ), f"{kex} is not a known KEM (not in {' '.join(known_kexes)})"
        assert (
            leaf in known_kexes or leaf in known_sigs
        ), f"{leaf} is not a known algorithm"
        assert (
            int is None or int in known_sigs
        ), f"{int} is not a known signature algorithm"
        assert (
            root is None or root in known_sigs
        ), f"{root} is not a known signature algorithm"
        assert (
            client_auth is None
            or client_auth in known_sigs
            or client_auth in known_kexes
        ), f"{client_auth} is not a known signature algorith or KEM"
        assert (
            client_ca is None or client_ca in known_sigs
        ), f"{client_ca} is not a known sigalg"


__validate_experiments()


def only_unique_experiments() -> None:
    """get unique experiments: one of each type"""
    global ALGORITHMS
    seen: set[tuple[ExperimentType, bool, bool]] = set()

    def update(exp: Experiment) -> Experiment:
        seen.add((exp.type, exp.client_auth is None, exp.keygen_cache))
        return exp

    ALGORITHMS = [
        update(exp)
        for exp in ALGORITHMS
        if (exp.type, exp.client_auth is None, exp.keygen_cache) not in seen
    ]


TIMER_REGEX = re.compile(r"(?P<label>[A-Z ]+): (?P<timing>\d+) ns")


def run_subprocess(
    command, working_dir: str = ".", expected_returncode: int = 0
) -> str:
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
        text=True,
        check=False,
    )
    assert (
        result.returncode == expected_returncode
    ), f"Failed to run '{command}':\n{result.stdout}"
    return result.stdout


def change_qdisc(ns: str, dev: str, pkt_loss: int, delay: str, rate=1000) -> None:
    if pkt_loss == 0:
        command: list[str] = [
            "ip",
            "netns",
            "exec",
            ns,
            "tc",
            "qdisc",
            "change",
            "dev",
            dev,
            "root",
            "netem",
            "limit",
            "1000",
            "delay",
            delay,
            "rate",
            f"{rate}mbit",
        ]
    else:
        command: list[str] = [
            "ip",
            "netns",
            "exec",
            ns,
            "tc",
            "qdisc",
            "change",
            "dev",
            dev,
            "root",
            "netem",
            "limit",
            "1000",
            "loss",
            "{0}%".format(pkt_loss),
            "delay",
            delay,
            "rate",
            f"{rate}mbit",
        ]

    logger.debug(" > " + " ".join(command))
    run_subprocess(command)


class ServerProcess(multiprocessing.Process):
    def __init__(
        self, port: int, pipe: Connection, experiment: Experiment, cached_int=False
    ):
        super().__init__(daemon=False)
        self.experiment = experiment
        self.path = get_experiment_path(experiment)
        self.port = str(port)
        self.pipe = pipe
        self.last_msg = "HANDSHAKE COMPLETED"
        self.servername = "tlsserver"
        self.type = experiment.type
        self.extra_opts: list[str] = []
        type = experiment.type
        if type == "sign" or type == "sign-cached":
            self.certname = "signing" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "signing.key"
        elif type == "kemtls" or type == "pdk":
            self.certname = "kem" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "kem.key"
        elif type == "optls":
            self.certname = "csidh" + (".chain" if not cached_int else "") + ".crt"
            self.keyname = "csidh.key"
        else:
            raise ValueError(f"Invalid Experiment type in {experiment}")

        if experiment.client_auth is not None:
            self.extra_opts += ["--require-auth", "--auth", "client-ca.crt"]

    def run(self):
        cmd: list[str] = [
            "ip",
            "netns",
            "exec",
            "srv_ns",
            f"./{self.servername}",
            "--certs",
            self.certname,
            "--key",
            self.keyname,
            "--port",
            self.port,
            *self.extra_opts,
            "http",
        ]
        logger.debug("Server cmd: %s", " ".join(cmd))
        self.server_process = subprocess.Popen(
            cmd,
            cwd=self.path,
            stdout=subprocess.PIPE,
            bufsize=8192 * 1024,
        )

        logger.debug(f"Launching server on port {self.port}")
        assert self.server_process.stdout is not None
        output_reader = io.TextIOWrapper(self.server_process.stdout, newline="\n")
        measurements: ResultType = {}
        collected_measurements: ResultListType = []
        connections = 0
        while (
            # collect one extra result for warmup
            len(collected_measurements) < MEASUREMENTS_PER_ITERATION
            and self.server_process.poll() is None
        ):
            line = output_reader.readline()
            if not line:
                logger.debug("Invalid line from server")
                break

            result = TIMER_REGEX.match(line)
            if result is not None:
                label = result.group("label")
                if label in measurements:
                    logger.error(
                        "We're adding the same label '%s' twice to the same measurement",
                        label,
                    )
                    logger.error("measurements=%r", measurements)
                    # XXX: this kills the measuring
                    if label == "RECEIVED CLIENT HELLO":
                        logger.warning("Resetting measurement")
                        measurements = {}
                    else:
                        raise ValueError(
                            f"label '{label}' already exisited in measurement"
                        )
                measurements[label] = result.group("timing")
                if label == self.last_msg:
                    if connections % (MEASUREMENTS_PER_CLIENT + 1) != 0:
                        collected_measurements.append(measurements)
                    else:
                        logger.debug(
                            "skipping warmup measurement data on connection %d",
                            connections,
                        )
                    connections += 1
                    measurements = {}
            else:
                logger.warn("Line '%s' did not match regex", line)

        logger.debug("[server] Sending data through pipe")
        self.pipe.send((" ".join(cmd), collected_measurements))
        time.sleep(1)

        logger.debug("Terminating server")
        self.server_process.terminate()
        try:
            self.server_process.wait(5)
        except subprocess.TimeoutExpired:
            logger.exception(
                "Timeout expired while waiting for server on {port} to terminate"
            )
            self.server_process.kill()


ExperimentOutput = tuple[str, str, list[tuple[ResultType, ResultType]]]


def run_measurement(
    output_queue: "multiprocessing.Queue[ExperimentOutput]",
    port,
    experiment: Experiment,
    cached_int,
):
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
    elif type == "optls":
        caname = "csidh" + ("-int" if cached_int else "-ca") + ".crt"
    else:
        logger.error("Unknown experiment type=%s", type)
        sys.exit(1)

    client_measurements: ResultListType = []
    restarts = 0
    allowed_restarts = 2 * MEASUREMENTS_PER_ITERATION / MEASUREMENTS_PER_CLIENT
    cache_args: list[str] = []
    if type == "pdk":
        cache_args = ["--cached-certs", "kem.crt"]
    elif type == "sign-cached":
        if not cached_int:
            cache_args = ["--cached-certs", "signing.all.crt"]
        else:
            cache_args = ["--cached-certs", "signing.chain.crt"]
    clientauthopts: list[str] = []
    if experiment.client_auth is not None:
        clientauthopts: list[str] = [
            "--auth-certs",
            "client.crt",
            "--auth-key",
            "client.key",
        ]
    cmd: List[str] = []
    expected_measurement_time: int = 200 if experiment.type == "optls" else 10
    while (
        len(client_measurements) < MEASUREMENTS_PER_ITERATION
        and server.is_alive()
        and restarts < allowed_restarts
    ):
        process_measurements: list[ResultType] = []
        logger.debug(f"Starting measurements on port {port}")
        cmd = [
            "ip",
            "netns",
            "exec",
            "cli_ns",
            f"./{clientname}",
            "--cafile",
            caname,
            "--loops",
            str(
                min(
                    MEASUREMENTS_PER_ITERATION - len(client_measurements),
                    MEASUREMENTS_PER_CLIENT,
                )
                + 1
            ),
            "--port",
            port,
            "--no-tickets",
            "--http",
            *cache_args,
            *clientauthopts,
            hostname,
        ]
        logger.debug("Client cmd: %s", " ".join(cmd))
        try:
            proc_result = subprocess.run(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                timeout=expected_measurement_time * MEASUREMENTS_PER_CLIENT + 1,
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
            server = ServerProcess(port, inpipe, experiment, cached_int=cached_int)
            server.start()
            continue

        logger.debug(f"Completed measurements on port {port}")
        measurement: ResultType = {}
        for line in proc_result.stdout.split("\n"):
            logger.debug("LINE FROM LOG: %s", line)
            assert "WebPKIError" not in line, f"Got WebPKIError in line '{line}'"
            result = TIMER_REGEX.match(line)
            if result:
                label: str = result.group("label")
                measurement[label] = result.group("timing")
                if label == LAST_MSG:
                    process_measurements.append(measurement)
                    measurement = {}
        # don't collect the warmup connection
        client_measurements.extend(process_measurements[1:])
        restarts += 1
    assert cmd != []

    logger.debug("Joining server")
    server.join(5)

    if not outpipe.poll(10):
        logger.error("No data available from server")
        sys.exit(1)
    (server_cmd, server_data) = cast(tuple[str, ResultListType], outpipe.recv())
    if len(server_data) != len(client_measurements):
        logger.error(
            f"Process on {port} out of sync {len(server_data)} != {len(client_measurements)}"
        )
        sys.exit(1)

    output: ExperimentOutput = (
        " ".join(cmd),
        server_cmd,
        list(zip(server_data, client_measurements)),
    )
    output_queue.put(output)


def experiment_run_timers(experiment: Experiment, cached_int: bool) -> ExperimentOutput:
    path = get_experiment_path(experiment)
    tasks = [(port, experiment, cached_int) for port in SERVER_PORTS]
    output_queue: multiprocessing.Queue[ExperimentOutput] = multiprocessing.Queue()
    processes = [
        multiprocessing.Process(target=run_measurement, args=(output_queue, *args))
        for args in tasks
    ]
    results: List[Tuple[str, str, List[Tuple[ResultType, ResultType]]]] = []
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

    flattened: Tuple[str, str, List[Tuple[ResultType, ResultType]]] = (
        results[0][0],
        results[0][1],
        [],
    )
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


def write_result(
    outfile: io.TextIOBase, outlog: io.TextIOBase, results: list[ExperimentOutput]
):
    client_cmd = results[0][0]
    server_cmd = results[0][1]
    server_keys = results[0][2][0][0].keys()
    client_keys = results[0][2][0][1].keys()
    keys = [f"client {key.lower()}" for key in client_keys] + [
        f"server {key.lower()}" for key in server_keys
    ]

    writer = csv.DictWriter(outfile, keys)
    writer.writeheader()
    outputs: list[tuple[ResultType, ResultType]] = []
    for r in results:
        outputs.extend(r[2])
    for (server_result, client_result) in outputs:
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
        logger.exception(
            "You probably need to set up '10.99.0.1' in servername in /etc/hosts"
        )
        raise


def get_filename(
    experiment: Experiment, int_only: bool, rtt_ms, pkt_loss, rate, ext="csv"
) -> Path:
    fileprefix = f"{experiment.kex}_{experiment.leaf}_{experiment.intermediate}"
    if not int_only:
        fileprefix += f"_{experiment.root}"
    if experiment.client_auth is not None:
        fileprefix += f"_clauth_{experiment.client_auth}_{experiment.client_ca}"
    fileprefix += f"_{rtt_ms}ms"
    caching_type = "int-chain" if not int_only else "int-only"
    keygen_cache = "-keycache" if experiment.keygen_cache else ""
    filename = (
        SCRIPTDIR.parent
        / "data"
        / f"{experiment.type}-{caching_type}{keygen_cache}"
        / f"{fileprefix}_{pkt_loss}_{rate}mbit.{ext}"
    )
    return filename


def setup_experiments() -> None:
    # get unique combinations
    combinations = set(
        get_experiment_instantiation(experiment) for experiment in ALGORITHMS
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
                experiment.client_auth or "",
                experiment.client_ca or "",
                "true" if experiment.keygen_cache else "",
            ],
            check=True,
            capture_output=False,
        )


def get_experiment_instantiation(experiment: Experiment) -> Experiment:
    # intermediate and root might be None, which means we'll need to match
    no_client_auth = experiment.client_auth is None
    for combo in ALGORITHMS:
        if all(
            map(
                lambda ab: ab[1] is None or ab[0] == ab[1],
                zip(combo[1:], experiment[1:]),
            )
        ):
            for (field, b) in experiment._asdict().items():
                if b is not None:
                    experiment._replace(**{field: getattr(combo, field)})
            break

    experiment = experiment._replace(
        intermediate=experiment.intermediate or "Dilithium2",
        root=experiment.root or "Dilithium2",
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
    if exp.keygen_cache:
        dirname += f"-keycache"
    return SCRIPTDIR.parent / Path("bin") / dirname


def main():
    os.makedirs("data", exist_ok=True)
    os.chown("data", uid=USERID, gid=GROUPID)
    for (type, caching, keycache) in itertools.product(
        ["kemtls", "sign", "sign-cached", "pdk", "optls"],
        ["int-chain", "int-only"],
        ["", "-keycache"],
    ):
        dirname = SCRIPTDIR.parent / "data" / f"{type}-{caching}{keycache}"
        os.makedirs(dirname, exist_ok=True)
        os.chown(dirname, uid=1001, gid=1001)

    for latency_ms in LATENCIES:
        # To get actual (emulated) RTT
        change_qdisc("cli_ns", "cli_ve", 0, delay=latency_ms)
        change_qdisc("srv_ns", "srv_ve", 0, delay=latency_ms)
        rtt_ms = get_rtt_ms()

        for (experiment, int_only, pkt_loss) in itertools.product(
            ALGORITHMS, [True, False], LOSS_RATES
        ):
            if "INT_ONLY" in os.environ and not int_only:
                continue
            if latency_ms == LATENCIES[0]:
                rate = 1000
            else:
                rate = 10
            (
                type,
                kex_alg,
                leaf,
                intermediate,
                root,
                client_auth,
                client_ca,
                keycache,
            ) = experiment
            if type in ("pdk", "sign-cached") and not int_only:
                # Skip PDK variants like KKDD, they don't make sense as the cert isn't sent.
                continue
            experiment = get_experiment_instantiation(experiment)
            logger.info(
                f"Experiment for {type} {kex_alg} {leaf} "
                + (f"{intermediate} " if intermediate is not None else "")
                + (f"{root} " if not int_only else "")
                + (
                    f"(client auth: {client_auth} signed by {client_ca}) "
                    if client_auth is not None
                    else ""
                )
                + f"for {rtt_ms}ms latency with "
                f"{'intermediate as CA' if int_only else 'full cert chain'}"
                f"{', cached ephemerals' if keycache else ''} "
                f"and {pkt_loss}% loss on {rate}mbit"
            )

            change_qdisc("cli_ns", "cli_ve", pkt_loss, delay=latency_ms, rate=rate)
            change_qdisc("srv_ns", "srv_ve", pkt_loss, delay=latency_ms, rate=rate)
            result: list[ExperimentOutput] = []
            fngetter = partial(
                get_filename,
                experiment,
                int_only,
                rtt_ms,
                pkt_loss,
                rate,
            )
            start_time = datetime.datetime.utcnow()
            for _ in range(ITERATIONS):
                result.append(experiment_run_timers(experiment, int_only))
            duration = datetime.datetime.utcnow() - start_time
            num_results = sum(len(r[2]) for r in result)
            logger.info("took %s to collect %d results", duration, num_results)

            with open(fngetter("csv"), "w+") as outresult, open(
                fngetter("cmdline"), "w+"
            ) as outlog:
                write_result(outresult, outlog, result)
            os.chown(fngetter("csv"), uid=USERID, gid=GROUPID)
            os.chown(fngetter("cmdline"), uid=USERID, gid=GROUPID)


if __name__ == "__main__":
    level: int = getattr(logging, os.environ.get("DEBUG", "INFO"))
    logger = logging.getLogger("BENCHMARKER")
    logger.setLevel(level)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(CustomFormatter())

    logger.addHandler(ch)

    algs = ALGORITHMS
    logger.info("Starting with %s instantiations", len(algs))
    if (type := os.environ.get("EXPERIMENT")) is not None:
        algs = filter(lambda x: x.type == type, ALGORITHMS)
    if (kex := os.environ.get("KEX")) is not None:
        algs = filter(lambda x: x.kex == kex, ALGORITHMS)
    if (leaf := os.environ.get("LEAF")) is not None:
        algs = filter(lambda x: x.leaf == leaf, ALGORITHMS)
    if (intermediate := os.environ.get("INT")) is not None:
        algs = filter(lambda x: x.intermediate == intermediate, ALGORITHMS)
    if (root := os.environ.get("ROOT")) is not None:
        algs = filter(lambda x: x.root == root, ALGORITHMS)
    if "NO_CLIENT_AUTH" in os.environ:
        algs = filter(lambda x: x.client_auth is None, ALGORITHMS)
    elif (client_auth := os.environ.get("CLIENT_AUTH")) is not None:
        algs = filter(lambda x: x.client_auth == client_auth, ALGORITHMS)
    if (client_ca := os.environ.get("CLIENT_CA")) is not None:
        algs = filter(lambda x: x.client_ca == client_ca, ALGORITHMS)
    ALGORITHMS = list(algs)

    if len(sys.argv) < 2 or sys.argv[1] != "full":
        logger.warning("Running only one experiment of each type")
        only_unique_experiments()

    logger.info(
        "Sign experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "sign"))
    )
    logger.info(
        "KEMTLS experiments: {}".format(
            sum(1 for alg in ALGORITHMS if alg[0] == "kemtls")
        )
    )
    logger.info(
        "PDK experiments: {}".format(sum(1 for alg in ALGORITHMS if alg[0] == "pdk"))
    )
    logger.info(
        "OPTLS experiments: {}".format(
            sum(1 for alg in ALGORITHMS if alg[0] == "optls")
        )
    )
    logger.info(
        "Sign-cached experiments: {}".format(
            sum(1 for alg in ALGORITHMS if alg[0] == "sign-cached")
        )
    )

    setup_experiments()
    hostname = reverse_resolve_hostname()
    main()
