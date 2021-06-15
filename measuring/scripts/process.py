#!/usr/bin/env python3

from collections import defaultdict
from itertools import chain
import csv
import os
import pathlib
import re
import statistics
import multiprocessing


DATAPATH = pathlib.Path(__file__).parent.absolute().parent / "data"
PROCESSED_PATH = DATAPATH / ".." / "processed"


#: Renames for the key exchange
KEX_RENAMES = {
    "X25519": "E",
    "SikeP434Compressed": "Sc",
}

SIG_RENAMES = {
    "RainbowICircumzenithal": "Rcz",
}

#: Renames for the leaf algorithm: combination of signature schemes and KEX
AUTH_RENAMES = dict()
AUTH_RENAMES.update(KEX_RENAMES)
AUTH_RENAMES.update(SIG_RENAMES)


def get_experiment_name(experiment):
    kex = experiment["kex"]
    leaf = experiment["leaf"]
    inter = experiment["int"]
    root = experiment["root"]
    clauth = experiment["clauth"]
    clca = experiment["clca"]

    type = ""
    if experiment["type"] == "pdk":
        type = "pdk"
    elif experiment["type"] == "kemtls":
        type = "kemtls"
    elif experiment["type"] == "sign-cached":
        type = "sigcache"
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

    return f"{type}{kex}{leaf}{inter}{root}{authpart}"


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


def get_averages(filename):
    sums = defaultdict(list)
    for line in read_csv_lines(filename):
        for key, val in line.items():
            sums[key].append(int(val) / 1000)  # convert to microseconds
    results = {}
    for key in sums.keys():
        results[key] = round(statistics.mean(sums[key]), 3)
        results[f"{key} stdev"] = round(statistics.stdev(sums[key]), 3)

    return (dict(results), len(sums[key]))


AVG_FIELDS = [
    "type",
    "kex",
    "leaf",
    "int",
    "root",
    "clauth",
    "clca",
    "int-only",
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


def format_results_tex(avgs):
    latency = float(avgs["rtt"])
    loss = avgs["drop_rate"]
    rate = avgs["rate"]

    macro_name_base = "res" + ("slow" if latency > 50 else "fast") + avgs['name']
    
    def macro(name, number):
        number = "%0.1f" % (number / 1000)
        return fr"\newcommand{{\{macro_name_base}{name}}}{{{number}}}  % {avgs['filename']}" "\n"

    with open(
        PROCESSED_PATH / f"processed_results_{latency:0.1f}_{loss}_{rate}.tex", "a+"
    ) as texfile:
        texfile.write(macro("encrypting", avgs["client writing to server"]))

        texfile.write(macro("clientdone", avgs["client handshake completed"]))
        texfile.write(macro("serverdone", avgs["server handshake completed"]))
        texfile.write(macro("serverexplicitauthed", avgs["client authenticated server"]))
        texfile.write(macro("clientgotreply", avgs["client received server reply"]))


def process_experiment(experiment):
    (filename, experiment) = experiment
    (avgs, count) = get_averages(filename)
    print(f"processed {filename} and got {count} points")
    avgs["measurements"] = count
    avgs.update(experiment)
    return avgs


def write_averages(experiments):
    names = set()

    with multiprocessing.Pool() as p:
        avgses = p.map(process_experiment, experiments)

    with open(PROCESSED_PATH / "avgs.csv", "w+") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=AVG_FIELDS)
        writer.writeheader()
        for avgs in avgses:
            name = avgs["name"]
            #print(f"{name}: from {avgs['filename']}")

            # Sanity check
            assert (name, avgs["rtt"]) not in names, f"Already seen {name}"
            names.add(name)
            
            print(f"{name}: Server reply: {avgs['client received server reply']}")
            print(f"{name}: Server done: {avgs['server handshake completed']}")
            writer.writerow(avgs)
            format_results_tex(avgs)


EXPERIMENT_REGEX = re.compile(
    r"(?P<type>(kemtls|sign|sign-cached|pdk))-(?P<cached>(int-chain|int-only))/"
    r"(?P<kex>[^_]+)_(?P<leaf>[^_]+)_(?P<int>[^_]+)(_(?P<root>[^_]+))?"
    r"(_clauth_(?P<clauth>[^_]+)_(?P<clca>[^_]+))?"
    r"_(?P<rtt>\d+\.\d+)ms_(?P<drop_rate>\d+(\.\d+)?)_(?P<rate>\d+mbit).csv"
)


def get_experiments():
    filenames = DATAPATH.glob("*/*.csv")
    return [(filename, get_experiment(filename)) for filename in filenames]


def get_experiment(filename):
    relpath = str(filename.relative_to(DATAPATH))
    matches = EXPERIMENT_REGEX.match(relpath)
    assert matches, f"Experiment '{relpath}' doesn't match regex"
    experiment = {}
    experiment["int-only"] = matches.group("cached") == "int-only"
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

    if experiment["int-only"]:
        assert experiment["root"] is None

    experiment["name"] = get_experiment_name(experiment)

    return experiment


def main():
    os.makedirs(DATAPATH / ".." / "processed", exist_ok=True)
    write_averages(get_experiments())


if __name__ == "__main__":
    main()
