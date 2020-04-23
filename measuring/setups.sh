set -e

cd ..

# Signed KEX
# Min w/o cache
#./create-experimental-setup.sh sikep434compressed Falcon512 XMSSs RainbowIaCyclic
# Min w/ cache (covered below)
#./create-experimental-setup.sh sikep434compressed Falcon512 RainbowIaCyclic RainbowIaCyclic
# Ass: MLWE
#./create-experimental-setup.sh kyber512 Dilithium2 Dilithium2 Dilithium2
# Ass: NTRU
#./create-experimental-setup.sh ntruhps2048509 Falcon512 Falcon512 Falcon512

# KEM-TLS
# Min w/o cache (covered above)
#./create-experimental-setup.sh sikep424compressed <ANYALG> XMSSs RainbowIaCyclic
# Min: w/ cached
./create-experimental-setup.sh sikep434compressed Falcon512 RainbowIaCyclic RainbowIaCyclic
# Ass: MLWE
./create-experimental-setup.sh kyber512 Dilithium2 Dilithium2 Dilithium2
# Ass: NTRU
./create-experimental-setup.sh ntruhps2048509 Falcon512 Falcon512 Falcon512
