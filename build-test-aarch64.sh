#!/bin/bash

set -e

#gcc -c -g -Wall -Wextra -O2 -o _bsaes_key_convert.o _bsaes_key_convert.c
#gcc -g -o _bsaes_key_convert _bsaes_key_convert.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

#gcc -c -g -Wall -Wextra -O2 -o _bsaes_decrypt8.o _bsaes_decrypt8.c
#gcc -g -o _bsaes_decrypt8 _bsaes_decrypt8.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

#gcc -c -g -Wall -Wextra -O2 -o _bsaes_encrypt8.o _bsaes_encrypt8.c
#gcc -g -o _bsaes_encrypt8 _bsaes_encrypt8.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

gcc -c -g -Wall -Wextra -O2 -o bsaes_ctr32_encrypt_blocks.o bsaes_ctr32_encrypt_blocks.c
gcc -g -o bsaes_ctr32_encrypt_blocks bsaes_ctr32_encrypt_blocks.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

gcc -c -g -Wall -Wextra -O2 -o bsaes_cbc_encrypt.o bsaes_cbc_encrypt.c
gcc -g -o bsaes_cbc_encrypt bsaes_cbc_encrypt.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

gcc -c -g -Wall -Wextra -O2 -o bsaes_xts_decrypt.o bsaes_xts_decrypt.c
gcc -g -o bsaes_xts_decrypt bsaes_xts_decrypt.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

gcc -c -g -Wall -Wextra -O2 -o bsaes_xts_encrypt.o bsaes_xts_encrypt.c
gcc -g -o bsaes_xts_encrypt bsaes_xts_encrypt.o crypto/aes/bsaes-armv8.o crypto/aes/aes_cbc.o crypto/modes/cbc128.o crypto/aes/aes_core.o

#objdump -d _bsaes_key_convert.o
#objdump -d _bsaes_decrypt8.o
#objdump -d _bsaes_encrypt8.o
#objdump -d bsaes_ctr32_encrypt_blocks.o
#objdump -d bsaes_cbc_encrypt.o
#objdump -d bsaes_xts_decrypt.o
objdump -d bsaes_xts_encrypt.o
