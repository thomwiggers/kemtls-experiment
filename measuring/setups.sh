
cd ..

# KEM-certs and signed KEX
# Min no cache
#./create-experimental-setup.sh RainbowIaCyclic XMSSs SikeP434Compressed
# Min: cached
./create-experimental-setup.sh RainbowIaCyclic RainbowIaCyclic SikeP434Compressed
# Ass: MLWE
./create-experimental-setup.sh Dilithium2 Dilithium2 Kyber512
# Ass: NTRU
./create-experimental-setup.sh Falcon512 Falcon512 ntruhps2048509
