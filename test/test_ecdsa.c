/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>

int main() {
    int i, c;
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};

    const struct Curve_t * curves[5];
    int num_curves = 0;
    curves[num_curves++] = secp256k1();

    
    printf("Testing 256 signatures\n");
    for (c = 0; c < num_curves; ++c) {
        for (i = 0; i < 256; ++i) {
            printf(".");
            fflush(stdout);

            if (!curve_make_key(public, private, curves[c])) {
                printf("curve_make_key() failed\n");
                return 1;
            }
            memcpy(hash, public, sizeof(hash));
            
            if (!curve_sign(private, hash, sizeof(hash), sig, curves[c])) {
                printf("curve_sign() failed\n");
                return 1;
            }

            if (!curve_verify(public, hash, sizeof(hash), sig, curves[c])) {
                printf("curve_verify() failed\n");
                return 1;
            }
        }
        printf("\n");
    }
    
    return 0;
}
