#!/bin/bash
gcc -I. uECC.c test/ecdsa_test_vectors.c -o ecdsa_test_vectors
gcc -I. uECC.c test/public_key_test_vectors.c -o public
gcc -I. uECC.c test/test_compute.c -o compute
gcc -I. uECC.c test/test_ecdh.c -o echdh
gcc -I. uECC.c test/test_ecdsa.c -o ecdsa



