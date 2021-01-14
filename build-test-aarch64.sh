#!/bin/bash

set -e
gcc -c -g -Wall -Wextra -O2 -o _bsaes_key_convert.o _bsaes_key_convert.c
gcc -o _bsaes_key_convert _bsaes_key_convert.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o
objdump -d _bsaes_key_convert.o
