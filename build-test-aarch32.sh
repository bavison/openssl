#!/bin/bash

set -e
rsync -av 192.168.0.172:openssl/_bsaes_key_convert.c .
rsync -av 192.168.0.172:openssl/build-test-aarch32.sh .
rsync -av 192.168.0.172:openssl/build-test-aarch64.sh .
gcc -c -mfpu=neon-vfpv4 -g -Wall -Wextra -O2 -o _bsaes_key_convert.o _bsaes_key_convert.c
gcc -g -o _bsaes_key_convert _bsaes_key_convert.o crypto/aes/bsaes-armv7.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes-armv4.o
objdump -d _bsaes_key_convert.o
