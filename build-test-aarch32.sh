#!/bin/bash

set -e
rsync -av 192.168.0.172:openssl/_bsaes_decrypt8.c .
rsync -av 192.168.0.172:openssl/_bsaes_encrypt8.c .
rsync -av 192.168.0.172:openssl/_bsaes_key_convert.c .
rsync -av 192.168.0.172:openssl/bsaes_ctr32_encrypt_blocks.c .
rsync -av 192.168.0.172:openssl/bsaes_cbc_encrypt.c .
rsync -av 192.168.0.172:openssl/bsaes_xts_decrypt.c .
rsync -av 192.168.0.172:openssl/tester.h .
rsync -av 192.168.0.172:openssl/build-test-aarch32.sh .
rsync -av 192.168.0.172:openssl/build-test-aarch64.sh .

gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o _bsaes_key_convert.o _bsaes_key_convert.c
gcc -g -o _bsaes_key_convert _bsaes_key_convert.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o

gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o _bsaes_decrypt8.o _bsaes_decrypt8.c
gcc -g -o _bsaes_decrypt8 _bsaes_decrypt8.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o

gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o _bsaes_encrypt8.o _bsaes_encrypt8.c
gcc -g -o _bsaes_encrypt8 _bsaes_encrypt8.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o

gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o bsaes_ctr32_encrypt_blocks.o bsaes_ctr32_encrypt_blocks.c
gcc -g -o bsaes_ctr32_encrypt_blocks bsaes_ctr32_encrypt_blocks.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o

gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o bsaes_cbc_encrypt.o bsaes_cbc_encrypt.c
gcc -g -o bsaes_cbc_encrypt bsaes_cbc_encrypt.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o

gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o bsaes_xts_decrypt.o bsaes_xts_decrypt.c
gcc -g -o bsaes_xts_decrypt bsaes_xts_decrypt.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o

#objdump -d _bsaes_key_convert.o
#objdump -d _bsaes_decrypt8.o
#objdump -d _bsaes_encrypt8.o
#objdump -d bsaes_ctr32_encrypt_blocks.o
#objdump -d bsaes_cbc_encrypt.o
objdump -d bsaes_xts_decrypt.o
