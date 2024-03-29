CEG 4750/6750 –  Information Security
Project 2
Professor Meilin Liu
March 28th, 2024
To compile files:
srun singularity exec /home/containers/cryptopp.sif g++ aes_decode_CTR.cpp -lcryptopp -o CTR_dec
srun singularity exec /home/containers/cryptopp.sif g++ aes_encode_CTR.cpp -lcryptopp -o CTR_enc
To run files:
./CTR_enc MSG1 MSG1.enc  000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f
./CTR_enc MSG1.enc MSG1.dec 000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f