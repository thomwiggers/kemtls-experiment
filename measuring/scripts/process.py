#!/usr/bin/env python3

from collections import defaultdict
from itertools import chain
import csv
import json
import os
from pathlib import Path
import re
import statistics
import multiprocessing

from typing import Any, Literal, Optional, Union, cast

from experiment import ALGORITHMS, Experiment

BASEPATH = Path(__file__).parent.absolute().parent

DATAPATH = BASEPATH / "data"
PROCESSED_PATH = BASEPATH / "processed"


#: Renames for the key exchange
KEX_RENAMES: dict[str, str] = {
    "X25519": "E",
    "Kyber768": "Kiii",
    "Dilithium3": "Diii",
    "Falcon1024": "Fv",
    "SikeP434Compressed": "Sc",
    "CTIDH512": "Ctfivetwelve",
    "CTIDH1024": "Cttentwentyfour",
    "CSIDH2047M1L226": "Cs",
    "CTIDH2047M1L226": "Ct",
    "CSIDH4095M27L262": "CsIc",
    "CTIDH4095M27L262": "CtIc",
    "CTIDH5119M46L244": "CtIIf",
}

SIG_RENAMES: dict[str, str] = {
    "RainbowICircumzenithal": "Rcz",
}

#: Renames for the leaf algorithm: combination of signature schemes and KEX
AUTH_RENAMES = dict()
AUTH_RENAMES.update(KEX_RENAMES)
AUTH_RENAMES.update(SIG_RENAMES)

ExperimentType = Union[
    Literal["sig"],
    Literal["pdk"],
    Literal["kemtls"],
    Literal["sigcache"],
    Literal["optls"],
]


def get_experiment_name(experiment: dict[str, Any]) -> str:
    kex = experiment["kex"]
    leaf = experiment["leaf"]
    inter = experiment["int"]
    root = experiment["root"]
    clauth = experiment["clauth"]
    clca = experiment["clca"]
    keycache = experiment["keycache"]

    type: Optional[ExperimentType] = None
    if experiment["type"] == "pdk":
        type = "pdk"
    elif experiment["type"] == "kemtls":
        type = "kemtls"
    elif experiment["type"] == "sign-cached":
        type = "sigcache"
    elif experiment["type"] == "optls":
        type = "optls"
    else:
        assert experiment["type"] == "sign", f"{experiment['type']} unknown"
        type = "sig"

    kex = KEX_RENAMES.get(kex, kex[0].upper())
    leaf = AUTH_RENAMES.get(leaf, leaf[0].upper())
    if inter is not None and type not in ("pdk", "sigcache"):
        inter = SIG_RENAMES.get(inter, inter[0].upper())
    elif inter is None or type in ("pdk", "sigcache"):
        inter = ""
    if root is not None and type != "pdk":
        root = SIG_RENAMES.get(root, root[0].upper())
    elif root is None or type == "pdk":
        root = ""

    authpart = ""
    if clauth is not None:
        clauth = AUTH_RENAMES.get(clauth, clauth[0].upper())
        clca = SIG_RENAMES.get(clca, clca[0].upper())
        authpart = f"auth{clauth}{clca}"

    keycache = ""
    if experiment["keycache"]:
        keycache = "keycache"

    return f"{type}{kex}{leaf}{inter}{root}{authpart}{keycache}"


def read_csv_lines(filename):
    """Read the entries from a csv"""
    with open(filename, "r") as file_:
        reader = csv.DictReader(file_)
        for line in reader:
            valid = True
            for key, val in line.items():
                if not val:
                    print("Invalid value for {} on line {}".format(key, line))
                    valid = False
                    break
            if valid:
                yield line


def get_averages(filename: Union[str, Path]) -> tuple[dict[str, float], int]:
    sums: defaultdict[str, list] = defaultdict(list)
    for line in read_csv_lines(filename):
        for key, val in line.items():
            sums[key].append(int(val) / 1000)  # convert to microseconds
    results: dict[str, float] = dict()
    key = None
    for key in sums.keys():
        results[key] = round(statistics.mean(sums[key]), 3)
        results[f"{key} stdev"] = round(statistics.stdev(sums[key]), 3)
        results[f"{key} var%"] = round(statistics.stdev(sums[key])/statistics.mean(sums[key])*100, 3)
    assert key is not None

    return (results, len(sums[key]))


AVG_FIELDS: list[str] = [
    "type",
    "kex",
    "leaf",
    "int",
    "root",
    "clauth",
    "clca",
    "int-only",
    "keycache",
    "rtt",
    "drop_rate",
    "rate",
    "measurements",
    "name",
    "filename",
    # client keys
    *chain.from_iterable(
        (f"client {key}", f"client {key} stdev")
        for key in [
            "start",
            "creating keyshares",
            "created keyshares",
            "created pdk encapsulation",
            "sending chelo",
            "received sh",
            "decapsulating ephemeral",
            "decapsulated ephemeral",
            "derived hs",
            "received cert",
            "submitted ckex to server",
            "encapsulating to cert",
            "encapsulated to cert",
            "derived ahs",
            "emit cert",
            "decapsulating from ccert",
            "decapsulated from ccert",
            "derived ms",
            "emitted finished",
            "received finished",
            "authenticated server",
            "handshake completed",
            "writing to server",
            "received server reply",
        ]
    ),
    # server keys
    *chain.from_iterable(
        (f"server {key}", f"server {key} stdev")
        for key in [
            "received client hello",
            "encapsulating to ephemeral",
            "encapsulated to ephemeral",
            "emitted sh",
            "pdk decapsulating from certificate",
            "pdk decapsulating from certificate",
            "pdk decapsulated from certificate",
            "derived hs",
            "pdk encapsulating to ccert",
            "pdk encapsulated to ccert",
            "emitted certificate",
            "emitting certv",
            "received ckex",
            "decapsulating from certificate",
            "decapsulated from certificate",
            "derived ahs",
            "received certificate",
            "encapsulating to client",
            "submitted skex to client",
            "received certv",
            "received finished",
            "authenticated client",
            "emitted finished",
            "reading traffic",
            "writing to client",
            "handshake completed",
        ]
    ),
]


def format_results_tex(avgs: dict[str, Any]):
    latency = float(avgs["rtt"])
    loss: str = avgs["drop_rate"]
    rate: str = avgs["rate"]

    macro_name_base = "res" + ("slow" if latency > 50 else "fast") + avgs["name"]

    def macro(name, number):
        number = "%0.1f" % (number / 1000)
        return (
            fr"\newcommand{{\{macro_name_base}{name}}}{{{number}}}  % {avgs['filename']}"
            "\n"
        )

    with open(
        PROCESSED_PATH / f"processed_results_{latency:0.1f}_{loss}_{rate}.tex", "a+"
    ) as texfile:
        texfile.write(macro("encrypting", avgs["client writing to server"]))

        texfile.write(macro("clientdone", avgs["client handshake completed"]))
        texfile.write(macro("serverdone", avgs["server handshake completed"]))
        texfile.write(
            macro("serverexplicitauthed", avgs["client authenticated server"])
        )
        texfile.write(macro("clientgotreply", avgs["client received server reply"]))


def process_experiment(
    experiment: tuple[str, dict[str, Union[int, float, bool, str]]]
) -> dict[str, Union[int, float, bool, str]]:
    (filename, data) = experiment
    (the_avgs, count) = get_averages(filename)
    avgs = cast(dict[str, Union[float, int, bool, str]], the_avgs)
    print(f"processed {filename} and got {count} points")
    avgs["measurements"] = count
    avgs.update(data)
    return avgs


# https://stackoverflow.com/a/54392761/248065
def dump_lua(data) -> str:
    if type(data) is str:
        return f'"{data}"'
    if type(data) in (int, float):
        return f"{data}"
    if type(data) is bool:
        return data and "true" or "false"
    if type(data) is list:
        l = "{"
        l += ", ".join([dump_lua(item) for item in data])
        l += "}"
        return l
    if type(data) is dict:
        t = "{"
        t += ", ".join([f'["{k}"]={dump_lua(v)}' for k, v in data.items()])
        t += "}"
        return t

    assert False, f"Unknown type {type(data)}"


def write_averages(experiments):
    names = set()

    with multiprocessing.Pool() as p:
        avgses = p.map(process_experiment, experiments)

    with open(PROCESSED_PATH / "avgs.csv", "w") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=AVG_FIELDS)
        writer.writeheader()
        for avgs in avgses:
            name = avgs["name"]
            # print(f"{name}: from {avgs['filename']}")

            # Sanity check
            assert (name, avgs["rtt"]) not in names, f"Already seen {name}"
            names.add(name)

            print(f"{name}: {avgs['rtt']} Server reply: {avgs['client received server reply']:0.1f} (+- {avgs['client received server reply var%']:0.1f})")
            print(f"{name}: {avgs['rtt']} Server done: {avgs['server handshake completed']:0.1f}")
            writer.writerow({key: val for key, val in avgs.items() if "%" not in key})
            format_results_tex(avgs)

    lua_table = dict()
    for avgs in avgses:
        item = lua_table
        for key_item in ("type", "rtt", "kex", "leaf", "int", "root", "clauth", "clca", "keycache"):
            key = avgs[key_item] or "none"
            if key_item == "rtt":
                key = f"{float(key):0.1f}"
            elif key_item == "keycache":
                key = "true" if avgs[key_item] else "false"
            if key not in item:
                item[key] = {}
            item = item[key]
        for key_item in avgs.keys():
            if key_item.startswith("server ") or key_item.startswith("client "):
                val = avgs[key_item]
                assert isinstance(val, (int, float))
                item[key_item] = val / 1000
            elif key_item == "measurements":
                val = avgs[key_item]
                item[key_item] = val

    with open(PROCESSED_PATH / "avgs.lua", "w") as luafile:
        luafile.write("measurement_results=")
        luafile.write(dump_lua(lua_table))
    with open(PROCESSED_PATH / "avgs.json", "w") as fh:
        json.dump(lua_table, fh, indent=2)


EXPERIMENT_REGEX = re.compile(
    r"(?P<type>(kemtls|sign|sign-cached|optls|pdk))(-(?P<cached>(int-chain|int-only)))?(-(?P<keycache>keycache))?/"
    r"(?P<kex>[^_]+)_(?P<leaf>[^_]+)(_(?P<int>[^_]+))?(_(?P<root>[^_]+))?"
    r"(_clauth_(?P<clauth>[^_]+)_(?P<clca>[^_]+))?"
    r"_(?P<rtt>\d+\.\d+)ms_(?P<drop_rate>\d+(\.\d+)?)_(?P<rate>\d+mbit).csv"
)


def get_experiments() -> list[tuple[Path, dict[str, Any]]]:
    filenames = DATAPATH.glob("*/*.csv")
    return [(filename, get_experiment(filename)) for filename in filenames]


def get_experiment(filename) -> dict[str, Union[int, float, bool, str]]:
    relpath = str(filename.relative_to(DATAPATH))
    matches = EXPERIMENT_REGEX.match(relpath)
    assert matches, f"Experiment '{relpath}' doesn't match regex"
    experiment: dict[str, Union[int, bool, str, float]] = {}
    experiment["filename"] = filename.name
    for item in [
        "type",
        "kex",
        "leaf",
        "int",
        "root",
        "clauth",
        "clca",
        "rtt",
        "drop_rate",
        "rate",
    ]:
        experiment[item] = matches.group(item)

    if experiment["type"] not in ("pdk", "sign-cached"):
        experiment["int-only"] = matches.group("cached") == "int-only"
    else:
        experiment["int-only"] = True
        assert matches.group("cached") is None
        assert experiment["int"] is None
        assert experiment["root"] is None
        assert matches.group("int") is None

    experiment["keycache"] = matches.group("keycache") == "keycache"

    if experiment["int-only"]:
        assert experiment["root"] is None

    experiment["name"] = get_experiment_name(experiment)

    return experiment


def create_handle(experiment: Experiment) -> str:
    def get_handle(alg: Optional[str]) -> str:
        if alg is None:
            return ""
        if alg == "X25519":
            return "e"
        if alg == "RSA2048":
            return "r"
        if alg.startswith("ClassicMcEliece"):
            return "M"
        if alg.startswith("Sphincs"):
            if "f" in alg:
                return "Sf"
            return "Ss"
        return alg[0]

    output = (
        get_handle(experiment.kex)
        + get_handle(experiment.leaf)
        + get_handle(experiment.intermediate)
        + get_handle(experiment.root)
    )
    if experiment.client_auth:
        output += "-" + get_handle(experiment.client_auth)
        output += get_handle(experiment.client_ca)

    return output


def produce_experiment_list():
    algs = []
    for experiment in ALGORITHMS:
        alg = {"handle": create_handle(experiment)}
        for attr in (
            "type",
            "level",
            "kex",
            "leaf",
            "intermediate",
            "root",
            "client_auth",
            "client_ca",
        ):
            if (a := getattr(experiment, attr)) is not None:
                alg[attr] = a
        algs.append(alg)
    with Path(BASEPATH / "processed" / "experiments.json").open("w") as fh:
        json.dump(algs, fh, indent=2)


def main():
    os.makedirs(DATAPATH / ".." / "processed", exist_ok=True)
    write_averages(get_experiments())
    produce_experiment_list()


if __name__ == "__main__":
    main()
