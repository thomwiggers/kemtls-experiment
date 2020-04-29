#!/usr/bin/env python3

from collections import defaultdict
from itertools import chain
import csv
import os
import pathlib
import re
import statistics


DATAPATH = pathlib.Path(__file__).parent.absolute().parent / 'data'


def read_csv_lines(filename):
    """Read the entries from a csv"""
    with open(filename, 'r') as file_:
        reader = csv.DictReader(file_)
        for line in reader:
            valid = True
            for val in line.values():
                if not val:
                    valid = False
                    break
            if valid:
                yield line


def get_averages(filename):
    sums = defaultdict(list)
    for line in read_csv_lines(filename):
        for key, val in line.items():
            sums[key].append(int(val)/1000)      # convert to microseconds
    results = {}
    for key in sums.keys():
        results[f'{key} stdev'] = statistics.stdev(sums[key])
        results[key] = statistics.mean(sums[key])

    return (dict(results), len(sums[key]))


AVG_FIELDS = [
    'type', 'kex', 'leaf', 'int', 'root', 'cached_int', 'rtt', 'drop_rate',
    'measurements',
    # client keys
    *chain.from_iterable(
        (f'client {key}', f'client {key} stdev')
        for key in
        ['emitted ch', 'derived ephemeral keys', 'received sh',
         'encapsulating to server', 'submitted ckex to server',
         'switched to ahs keys', 'client encrypting traffic',
         'authenticated server', 'handshake completed']),
    # server keys
    *chain.from_iterable(
        (f'server {key}', f'server {key} stdev')
        for key in
        ['encapsulated ephemeral', 'emitted sh', 'derived ephemeral keys',
         'decapsulated from client', 'switched to ahs keys',
         'emitted sf', 'server encrypting traffic', 'server reading traffic',
         'handshake completed']),
]


def write_averages(experiments):
    with open(DATAPATH / '..' / 'processed' / 'avgs.csv', 'w+') as f:
        writer = csv.DictWriter(f, fieldnames=AVG_FIELDS)
        writer.writeheader()
        for (filename, experiment) in experiments:
            (avgs, count) = get_averages(filename)
            avgs['measurements'] = count
            avgs.update(experiment)
            writer.writerow(avgs)


EXPERIMENT_REGEX = re.compile(
        r"(?P<type>(kem|sign))-(?P<cached>(int-chain|cached))/"
        r"(?P<kex>[^_]+)_(?P<leaf>[^_]+)_(?P<int>[^_]+)(_(?P<root>[^_]+))?"
        r"_(?P<rtt>\d+\.\d+)ms_(?P<drop_rate>\d+(\.\d+)?).csv"
        )

def get_experiments():
    experiments = []
    for filename in DATAPATH.glob("*/*.csv"):
        relpath = str(filename.relative_to(DATAPATH))
        matches = EXPERIMENT_REGEX.match(relpath)
        experiment = {}
        experiment['cached_int'] = matches.group('cached') == 'cached'
        for item in ['type', 'kex', 'leaf', 'int', 'root', 'rtt', 'drop_rate']:
            experiment[item] = matches.group(item)

        experiments.append((filename, experiment))
    return experiments


def main():
    os.makedirs(DATAPATH / '..' / 'processed', exist_ok=True)
    write_averages(get_experiments())


if __name__ == "__main__":
    main()
