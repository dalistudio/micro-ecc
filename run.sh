#!/bin/bash
gcc -I. curve.c bigint.c test/ecdsa_test_vectors.c -o ecdsa_test_vectors
gcc -I. curve.c bigint.c test/public_key_test_vectors.c -o public
gcc -I. curve.c bigint.c test/test_compute.c -o compute
gcc -I. curve.c bigint.c test/test_ecdh.c -o ecdh
gcc -I. curve.c bigint.c test/test_ecdsa.c -o ecdsa



