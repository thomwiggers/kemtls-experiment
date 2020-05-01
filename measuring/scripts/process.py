#!/usr/bin/env python3

from collections import defaultdict
from itertools import chain
import csv
import os
import pathlib
import re
import statistics


DATAPATH = pathlib.Path(__file__).parent.absolute().parent / 'data'
PROCESSED_PATH = DATAPATH / '..' / 'processed'

def get_experiment_name(kex, leaf, inter, root):
    if kex == 'X25519':
        kex = 'E'

    return f"{kex[0]}{leaf[0]}{inter[0]}{root[0] if root else ''}".upper()


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
        results[key] = mean = statistics.mean(sums[key])
        results[f'{key} stdev'] = stdev = statistics.stdev(sums[key])
        results[f'{key} rel stdev'] = stdev / mean * 100

    return (dict(results), len(sums[key]))


AVG_FIELDS = [
    'type', 'kex', 'leaf', 'int', 'root', 'cached_int', 'rtt', 'drop_rate', 'rate',
    'measurements', 'name',
    # client keys
    *chain.from_iterable(
        (f'client {key}', f'client {key} stdev', f'client {key} rel stdev')
        for key in
        ['emitted ch', 'derived ephemeral keys', 'received sh',
         'encapsulating to server', 'submitted ckex to server',
         'switched to ahs keys', 'client encrypting traffic',
         'authenticated server', 'handshake completed']),
    # server keys
    *chain.from_iterable(
        (f'server {key}', f'server {key} stdev', f'server {key} rel stdev')
        for key in
        ['encapsulated ephemeral', 'emitted sh', 'derived ephemeral keys',
         'decapsulated from client', 'switched to ahs keys',
         'emitted sf', 'server encrypting traffic', 'server reading traffic',
         'handshake completed']),
]


def format_results_tex(avgs):
    latency = avgs['rtt']
    loss = avgs['drop_rate']
    rate = avgs['rate']

    macro_name_base = f"res{avgs['name']}"

    def macro(name, number):
        number = "%0.1f" % (number/1000)
        return fr"\newcommand{{\{macro_name_base}{name}}}{{{number}}}""\n"

    with open(PROCESSED_PATH / f'processed_results_{latency}_{loss}_{rate}.tex',
              'a+') as texfile:
        if avgs['type'] == 'kem':
            texfile.write(
                macro('encrypting', avgs['client client encrypting traffic']))
        elif avgs['type'] == 'sign':
            texfile.write(
                macro('encrypting', avgs['client handshake completed']))

        texfile.write(macro('clientdone', avgs['client handshake completed']))
        texfile.write(macro('serverdone', avgs['server handshake completed']))



def write_averages(experiments):
    with open(PROCESSED_PATH / 'avgs.csv', 'w+') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=AVG_FIELDS)
        writer.writeheader()
        for (filename, experiment) in experiments:
            (avgs, count) = get_averages(filename)
            print(f"processed{filename} and got {count} points")
            avgs['measurements'] = count
            avgs.update(experiment)
            writer.writerow(avgs)
            format_results_tex(avgs)


EXPERIMENT_REGEX = re.compile(
        r"(?P<type>(kem|sign))-(?P<cached>(int-chain|cached))/"
        r"(?P<kex>[^_]+)_(?P<leaf>[^_]+)_(?P<int>[^_]+)(_(?P<root>[^_]+))?"
        r"_(?P<rtt>\d+\.\d+)ms_(?P<drop_rate>\d+(\.\d+)?)_(?P<rate>\d+mbit).csv"
        )

def get_experiments():
    experiments = []
    for filename in DATAPATH.glob("*/*.csv"):
        relpath = str(filename.relative_to(DATAPATH))
        matches = EXPERIMENT_REGEX.match(relpath)
        assert matches
        experiment = {}
        experiment['cached_int'] = matches.group('cached') == 'cached'
        for item in ['type', 'kex', 'leaf', 'int', 'root', 'rtt', 'drop_rate', 'rate']:
            experiment[item] = matches.group(item)
        experiment['name'] = get_experiment_name(
            experiment['kex'], experiment['leaf'],
            experiment['int'], experiment['root'])

        experiments.append((filename, experiment))
    return experiments


def main():
    os.makedirs(DATAPATH / '..' / 'processed', exist_ok=True)
    write_averages(get_experiments())


if __name__ == "__main__":
    main()
