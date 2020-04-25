"""Based on https://github.com/xvzcf/pq-tls-benchmark/blob/master/emulation-exp/code/kex/experiment.py"""

import csv
import multiprocessing
import os
import io
import subprocess
import itertools
import time
import re

hostname = 'servername'

ALGORITHMS = (
    # Need to specify leaf to construct correct binary directory
    # EXPERIMENT - KEX - LEAF - INT - ROOT
    ('sign', 'sikep434compressed', 'Falcon512', 'XMSS', 'RainbowIaCyclic'),
    ('sign', 'sikep434compressed', 'Falcon512', 'RainbowIaCyclic', 'RainbowIaCyclic'),
    ('sign', 'kyber512', 'Dilithium2', 'Dilithium2', 'Dilithium2',),
    ('sign', 'ntruhps2048509', 'Falcon512', 'Falcon512', 'Falcon512'),
    ('kem', 'sikep434compressed', 'Falcon512', 'XMSS', 'RainbowIaCyclic'),
    ('kem', 'sikep434compressed', 'Falcon512', 'RainbowIaCyclic', 'RainbowIaCyclic'),
    ('kem', 'kyber512', 'Dilithium2', 'Dilithium2', 'Dilithium2',),
    ('kem', 'ntruhps2048509', 'Falcon512', 'Falcon512', 'Falcon512'),
)

LATENCIES = ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
LOSS_RATES = [0, 0.1] # 0.1, 0.5, 1, 1.5, 2, 2.5, 3] + list(range(4, 21)):
NUM_PINGS = 50  # for measuring the practical latency


# xvzcf's experiment used POOL_SIZE = 40
# We start as many servers as clients, so make sure to adjust accordingly
POOL_SIZE = 40

SERVER_PORTS = [str(port) for port in range(10000, 10000+POOL_SIZE)]

MEASUREMENTS_PER_PROCESS = 5000

TIMER_REGEX = re.compile(r"(?P<label>[A-Z ]+): (?P<timing>\d+) ns")


def run_subprocess(command, working_dir='.', expected_returncode=0):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
	text=True
    )
    assert result.returncode == expected_returncode, f"Failed to run '{command}'"
    return result.stdout


def change_qdisc(ns, dev, pkt_loss, delay):
    if pkt_loss == 0:
        command = [
            'ip', 'netns', 'exec', ns,
            'tc', 'qdisc', 'change',
            'dev', dev, 'root', 'netem',
            'limit', '1000',
            'delay', delay,
            'rate', '1000mbit'
        ]
    else:
        command = [
            'ip', 'netns', 'exec', ns,
            'tc', 'qdisc', 'change',
            'dev', dev, 'root', 'netem',
            'limit', '1000',
            'loss', '{0}%'.format(pkt_loss),
            'delay', delay,
            'rate', '1000mbit'
        ]

    #print(" > " + " ".join(command))
    run_subprocess(command)


class ServerProcess(multiprocessing.Process):
    def __init__(self, path, port, type, pipe, cached_int=False):
        super().__init__(daemon=False)
        self.path = path
        self.port = port
        self.pipe = pipe
        self.last_msg = 'HANDSHAKE COMPLETED'
        if type == "sign":
            self.servername = 'pqtlsserver'
            self.certname = 'signing' + ('.chain' if not cached_int else '') + '.crt'
            self.keyname = 'signing.key'
        else:
            self.servername = 'kemtlsserver'
            self.certname = 'kem' + ('.chain' if not cached_int else '') + '.crt'
            self.keyname = 'kem.key'

        self.server_process = subprocess.Popen(
            ['ip', 'netns', 'exec', 'srv_ns',
             f'./{self.servername}', '--certs', self.certname, '--key', self.keyname, '-p', self.port, 'http'],
            cwd=self.path,
            stdout=subprocess.PIPE,
            bufsize=8192*1024,
        )


    def run(self):
        print(f"[+] Launching server on port {self.port}")
        output_reader = io.TextIOWrapper(self.server_process.stdout, newline='\n')
        measurements = {}
        collected_measurements = []
        while True:
            line = output_reader.readline()
            if not line:
                break
            line.rstrip()
            result = TIMER_REGEX.match(line)
            if result:
                label = result.group('label')
                measurements[label] = result.group('timing')
                if label == self.last_msg:
                    collected_measurements.append(measurements)
                    measurements = {}
        self.pipe.send(collected_measurements)


def run_measurement_kem(output_queue, path, port, type, cached_int):
    (inpipe, outpipe) = multiprocessing.Pipe()
    server = ServerProcess(path, port, type, inpipe, cached_int)
    server.start()
    time.sleep(1)

    LAST_MSG = 'HANDSHAKE COMPLETED'
    if type == "sign":
        clientname = 'pqtlsclient'
        caname = 'signing' + ('-int' if cached_int else '-ca') + '.crt'
    else:
        clientname = 'kemtlsclient'
        caname = 'kem' + ('-int' if cached_int else '-ca') + '.crt'

    measurements = []
    print(f"[+] Starting measurements on port {port}")
    proc_result = subprocess.run(
        ['ip', 'netns', 'exec', 'cli_ns',
         f"./{clientname}", '--cafile', caname, '--loops', str(MEASUREMENTS_PER_PROCESS),
         '--port', port, '--http', hostname],
        text=True,
        stdout=subprocess.PIPE,
        timeout=3 * MEASUREMENTS_PER_PROCESS,
        check=True,
        cwd=path,
    )
    print(f"[+] Completed measurements on port {port}")
    client_measurements = []
    measurement = {}
    for line in proc_result.stdout.split("\n"):
        result = TIMER_REGEX.match(line)
        if result:
            label = result.group('label')
            measurement[label] = result.group('timing')
            if label == LAST_MSG:
                client_measurements.append(measurement)
                measurement = {}

    print(f"[+] Shutting down server on port {port}")
    server.server_process.terminate()
    server.join(5)

    server_data = outpipe.recv()
    assert len(server_data) == len(client_measurements) == MEASUREMENTS_PER_PROCESS, \
            f"{len(server_data)} != {len(client_measurements)} != {MEASUREMENTS_PER_PROCESS}"

    output_queue.put(list(zip(server_data, client_measurements)))
    server.close()


def kem_run_timers(path, type, cached_int):
    tasks = [(path, port, type, cached_int) for port in SERVER_PORTS]
    output_queue = multiprocessing.Queue()
    processes = [multiprocessing.Process(target=run_measurement_kem, args=(output_queue, *args)) for args in tasks]
    results = []
    for process in processes:
        process.start()

    # Consume output
    for _i in range(len(processes)):
        results.extend(output_queue.get())

    for process in processes:
        process.join()

    return results


def get_rtt_ms():
    print("[+] Pinging")
    command = [
        'ip', 'netns', 'exec', 'cli_ns',
        'ping', hostname, '-c', str(NUM_PINGS),
    ]

    #print(" > " + " ".join(command))
    result = run_subprocess(command)

    result_fmt = result.splitlines()[-1].split("/")
    return result_fmt[4]


def write_result(outfile, results):
    client_keys = results[0][0].keys()
    server_keys = results[0][1].keys()
    keys = [f'client {key.lower()}' for key in client_keys] + [f'server {key.lower()}' for key in server_keys]

    writer = csv.DictWriter(outfile, keys)
    writer.writeheader()
    for (client_result, server_result) in results:
        row = {f'client {key.lower()}': value for (key, value) in client_result.items()}
        row.update({f'server {key.lower()}': value for (key, value) in server_result.items()})
        writer.writerow(row)

def reverse_resolve_hostname():
    import socket
    return socket.gethostbyaddr("10.99.0.1")[0]

def main():
    reverse_resolve_hostname()
    os.makedirs(os.path.join('data', 'kem'), exist_ok=True)
    os.makedirs(os.path.join('data', 'sign'), exist_ok=True)

    for (cached_int, latency_ms) in itertools.product([True], LATENCIES):
        # To get actual (emulated) RTT
        change_qdisc('cli_ns', 'cli_ve', 0, delay=latency_ms)
        change_qdisc('srv_ns', 'srv_ve', 0, delay=latency_ms)
        rtt_str = get_rtt_ms()

        for (type, kex_alg, leaf, intermediate, root) in ALGORITHMS:
            print(f"[+] Experiment for {type} {kex_alg} {leaf} {intermediate} {root}")
            experiment_path = os.path.join("bin", f"{kex_alg}-{leaf}-{intermediate}-{root}")
            if cached_int:
                fileprefix = f"{kex_alg}_{intermediate}_{root}_{rtt_str}ms"
            else:
                fileprefix = f"{kex_alg}_{intermediate}_{rtt_str}ms"

            for pkt_loss in LOSS_RATES:
                print(f"[+] Measuring loss rate {pkt_loss}")
                change_qdisc('cli_ns', 'cli_ve', pkt_loss, delay=latency_ms)
                change_qdisc('srv_ns', 'srv_ve', pkt_loss, delay=latency_ms)
                result = kem_run_timers(experiment_path, type, cached_int)
                with open(f'data/{type}/{fileprefix}_{pkt_loss}.csv', 'w+') as out:
                    write_result(out, result)


if __name__ == "__main__":
    hostname = reverse_resolve_hostname()
    main()
