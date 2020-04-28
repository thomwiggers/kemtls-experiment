set -e

cd $(dirname $0)

# Signed KEX
# Classic TLS
./create-experimental-setup.sh X25519 RSA2048 RSA2048 RSA2048
# Min w/o cache
./create-experimental-setup.sh sikep434compressed Falcon512 XMSS RainbowIaCyclic
# Min w/ cache (covered below)
#./create-experimental-setup.sh sikep434compressed Falcon512 RainbowIaCyclic RainbowIaCyclic
# Ass: MLWE (covered below)
#./create-experimental-setup.sh kyber512 Dilithium2 Dilithium2 Dilithium2
# Ass: NTRU (covered below)
#./create-experimental-setup.sh ntruhps2048509 Falcon512 Falcon512 Falcon512

# KEM-TLS
# Min w/o cache (covered above)
#./create-experimental-setup.sh sikep424compressed <ANYALG> XMSSs RainbowIaCyclic
# Min: w/ cached + (sig falcon+cached rainbow)
./create-experimental-setup.sh sikep434compressed Falcon512 RainbowIaCyclic RainbowIaCyclic
# Ass: MLWE + (sig dilithium)
./create-experimental-setup.sh kyber512 Dilithium2 Dilithium2 Dilithium2
# Ass: NTRU (+ sig falcon chain)
./create-experimental-setup.sh ntruhps2048509 Falcon512 Falcon512 Falcon512
