set -e

cd $(dirname $0)

# Signed KEX
# Classic TLS
./create-experimental-setup.sh X25519 RSA2048 RSA2048 RSA2048
# Min w/o cache (Rainbow)
./create-experimental-setup.sh sikep434compressed falcon512 XMSS rainbowicyclic
# Min w/o cache (GeMSS)
#./create-experimental-setup.sh sikep434compressed Falcon512 XMSS Gemss128
# Min w/ cache (covered below)
#./create-experimental-setup.sh sikep434compressed Falcon512 RainbowIaCyclic RainbowIaCyclic
# Ass: MLWE (covered below)
#./create-experimental-setup.sh kyber512 Dilithium2 Dilithium2 Dilithium2
# Ass: NTRU (covered below)
#./create-experimental-setup.sh ntruhps2048509 Falcon512 Falcon512 Falcon512
# Minimal assumptions
./create-experimental-setup.sh kyber512 dilithium2 xmss xmss

# KEM-TLS
# Min w/o cache (covered above)
#./create-experimental-setup.sh sikep424compressed <ANYALG> XMSSs RainbowIaCyclic
# Min: w/ cached + (sig falcon+cached rainbow)
#./create-experimental-setup.sh sikep434compressed falcon512 RainbowIaCyclic RainbowIaCyclic
# Min: w/ cached + (sig falcon+cached gemss)
#./create-experimental-setup.sh sikep434compressed Falcon512 Gemss128 Gemss128
# Ass: MLWE + (sig dilithium)
#./create-experimental-setup.sh kyber512 Dilithium2 Dilithium2 Dilithium2
# Ass: NTRU (+ sig falcon chain)
#./create-experimental-setup.sh ntruhps2048509 Falcon512 Falcon512 Falcon512
