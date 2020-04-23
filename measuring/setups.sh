set -e

cd ..

# KEM-certs and signed KEX
# Min no cache
#./create-experimental-setup.sh RainbowIaCyclic XMSSs sikep434compressed
# Min: cached
./create-experimental-setup.sh RainbowIaCyclic RainbowIaCyclic sikep434compressed
# Ass: MLWE
./create-experimental-setup.sh Dilithium2 Dilithium2 kyber512
# Ass: NTRU
./create-experimental-setup.sh Falcon512 Falcon512 ntruhps2048509
