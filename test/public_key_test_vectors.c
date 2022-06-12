/* Copyright 2020, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char* k;
  const char* Q;
  int success;
} Test;

Test secp256k1_tests[] = {
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000001",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        0
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000002",
        "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE51AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
        1
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
        1
    },
    {   /* n - 4 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413D",
        "E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13AE1266C15F2BAA48A9BD1DF6715AEBB7269851CC404201BF30168422B88C630D",
        1
    },
    {   /* n - 3 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413E",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9C77084F09CD217EBF01CC819D5C80CA99AFF5666CB3DDCE4934602897B4715BD",
        1
    },
    {   /* n - 2 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F",
        "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5E51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705",
        0
    },
    {   /* n - 1 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777",
        0
    },
    {   /* n */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        0
    },
};


void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
    printf("\n");
}

void strtobytes(const char* str, uint8_t* bytes, int count) {
  for (int c = 0; c < count; ++c) {
    if (sscanf(str, "%2hhx", &bytes[c]) != 1) {
      printf("Failed to read string to bytes");
      exit(1);
    }
    str += 2;
  }
}

int run(Test* tests, int num_tests, Curve curve) {
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t expected[64] = {0};
    int result;
    int i;
    int private_key_size;
    int public_key_size;
    int all_success = 1;

    private_key_size = curve_private_key_size(curve);
    public_key_size = curve_public_key_size(curve);

    for (i = 0; i < num_tests; ++i) {
        strtobytes(tests[i].k, private, private_key_size);
        result = curve_compute_public_key(private, public, curve);
        if (result != tests[i].success) {
            all_success = 0;
            printf("  Got unexpected result from test %d: %d\n", i, result);
        }
        if (result) {
            strtobytes(tests[i].Q, expected, public_key_size);
            if (memcmp(public, expected, public_key_size) != 0) {
                all_success = 0;
                printf("  Got incorrect public key for test %d\n", i);
                printf("    Expected: ");
                vli_print(expected, public_key_size);
                printf("    Calculated: ");
                vli_print(public, public_key_size);
            }
        }
    }

    return all_success;
}

#define RUN_TESTS(curve) \
    printf(#curve ":\n"); \
    if (run(curve##_tests, sizeof(curve##_tests) / sizeof(curve##_tests[0]), secp256k1()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }

int main() {
    RUN_TESTS(secp256k1)
    return 0;
}
