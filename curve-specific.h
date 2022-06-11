/* Copyright 2015, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_CURVE_SPECIFIC_H_
#define _UECC_CURVE_SPECIFIC_H_

#define secp256k1_bytes 32

#define secp256k1_words 8

#define BYTES_TO_WORDS_8(a, b, c, d, e, f, g, h) 0x##d##c##b##a, 0x##h##g##f##e
#define BYTES_TO_WORDS_4(a, b, c, d) 0x##d##c##b##a


static void double_jacobian_secp256k1(big * X1, big * Y1, big * Z1, Curve curve);
static void x_side_secp256k1(big *result, const big *x, Curve curve);
static void vbi_mmod_fast_secp256k1(big *result, big *product);


static const struct Curve_t curve_secp256k1 = {
    secp256k1_words,
    secp256k1_bytes,
    256, /* num_n_bits */
    { BYTES_TO_WORDS_8(2F, FC, FF, FF, FE, FF, FF, FF),
        BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF),
        BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF),
        BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF) },
    { BYTES_TO_WORDS_8(41, 41, 36, D0, 8C, 5E, D2, BF),
        BYTES_TO_WORDS_8(3B, A0, 48, AF, E6, DC, AE, BA),
        BYTES_TO_WORDS_8(FE, FF, FF, FF, FF, FF, FF, FF),
        BYTES_TO_WORDS_8(FF, FF, FF, FF, FF, FF, FF, FF) },
    { BYTES_TO_WORDS_8(98, 17, F8, 16, 5B, 81, F2, 59),
        BYTES_TO_WORDS_8(D9, 28, CE, 2D, DB, FC, 9B, 02),
        BYTES_TO_WORDS_8(07, 0B, 87, CE, 95, 62, A0, 55),
        BYTES_TO_WORDS_8(AC, BB, DC, F9, 7E, 66, BE, 79),

        BYTES_TO_WORDS_8(B8, D4, 10, FB, 8F, D0, 47, 9C),
        BYTES_TO_WORDS_8(19, 54, 85, A6, 48, B4, 17, FD),
        BYTES_TO_WORDS_8(A8, 08, 11, 0E, FC, FB, A4, 5D),
        BYTES_TO_WORDS_8(65, C4, A3, 26, 77, DA, 3A, 48) },
    { BYTES_TO_WORDS_8(07, 00, 00, 00, 00, 00, 00, 00),
        BYTES_TO_WORDS_8(00, 00, 00, 00, 00, 00, 00, 00),
        BYTES_TO_WORDS_8(00, 00, 00, 00, 00, 00, 00, 00),
        BYTES_TO_WORDS_8(00, 00, 00, 00, 00, 00, 00, 00) },
    &double_jacobian_secp256k1,
    &x_side_secp256k1,
    &vbi_mmod_fast_secp256k1

};

Curve uECC_secp256k1(void) { return &curve_secp256k1; }


/* Double in place */
static void double_jacobian_secp256k1(big * X1, big * Y1, big * Z1, Curve curve) {
    /* t1 = X, t2 = Y, t3 = Z */
    big t4[secp256k1_words];
    big t5[secp256k1_words];
    
    if (vbi_is_zero(Z1, secp256k1_words)) {
        return;
    }
    
    vbi_mod_square_fast(t5, Y1, curve);   /* t5 = y1^2 */
    vbi_mod_mul_fast(t4, X1, t5, curve); /* t4 = x1*y1^2 = A */
    vbi_mod_square_fast(X1, X1, curve);   /* t1 = x1^2 */
    vbi_mod_square_fast(t5, t5, curve);   /* t5 = y1^4 */
    vbi_mod_mul_fast(Z1, Y1, Z1, curve); /* t3 = y1*z1 = z3 */
    
    vbi_mod_add(Y1, X1, X1, curve->p, secp256k1_words); /* t2 = 2*x1^2 */
    vbi_mod_add(Y1, Y1, X1, curve->p, secp256k1_words); /* t2 = 3*x1^2 */
    if (vbi_test_bit(Y1, 0)) {
        big carry = vbi_add(Y1, Y1, curve->p, secp256k1_words);
        vbi_rshift1(Y1, secp256k1_words);
        Y1[secp256k1_words - 1] |= carry << (WORD_BITS - 1);
    } else {
        vbi_rshift1(Y1, secp256k1_words);
    }
    /* t2 = 3/2*(x1^2) = B */
    
    vbi_mod_square_fast(X1, Y1, curve);                     /* t1 = B^2 */
    vbi_mod_sub(X1, X1, t4, curve->p, secp256k1_words); /* t1 = B^2 - A */
    vbi_mod_sub(X1, X1, t4, curve->p, secp256k1_words); /* t1 = B^2 - 2A = x3 */
    
    vbi_mod_sub(t4, t4, X1, curve->p, secp256k1_words); /* t4 = A - x3 */
    vbi_mod_mul_fast(Y1, Y1, t4, curve);                   /* t2 = B * (A - x3) */
    vbi_mod_sub(Y1, Y1, t5, curve->p, secp256k1_words); /* t2 = B * (A - x3) - y1^4 = y3 */
}

/* Computes result = x^3 + b. result must not overlap x. */
static void x_side_secp256k1(big *result, const big *x, Curve curve) {
    vbi_mod_square_fast(result, x, curve);                                /* r = x^2 */
    vbi_mod_mul_fast(result, result, x, curve);                          /* r = x^3 */
    vbi_mod_add(result, result, curve->b, curve->p, secp256k1_words); /* r = x^3 + b */
}


static void omega_mult_secp256k1(big *result, const big *right);
static void vbi_mmod_fast_secp256k1(big *result, big *product) {
    big tmp[2 * secp256k1_words];
    big carry;
    
    vbi_clear(tmp, secp256k1_words);
    vbi_clear(tmp + secp256k1_words, secp256k1_words);
    
    omega_mult_secp256k1(tmp, product + secp256k1_words); /* (Rq, q) = q * c */
    
    carry = vbi_add(result, product, tmp, secp256k1_words); /* (C, r) = r + q       */
    vbi_clear(product, secp256k1_words);
    omega_mult_secp256k1(product, tmp + secp256k1_words); /* Rq*c */
    carry += vbi_add(result, result, product, secp256k1_words); /* (C1, r) = r + Rq*c */
    
    while (carry > 0) {
        --carry;
        vbi_sub(result, result, curve_secp256k1.p, secp256k1_words);
    }
    if (vbi_cmp_unsafe(result, curve_secp256k1.p, secp256k1_words) > 0) {
        vbi_sub(result, result, curve_secp256k1.p, secp256k1_words);
    }
}

static void omega_mult_secp256k1(uint32_t * result, const uint32_t * right) {
    /* Multiply by (2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    uint32_t carry = 0;
    count k;
    
    for (k = 0; k < secp256k1_words; ++k) {
        uint64_t p = (uint64_t)0x3D1 * right[k] + carry;
        result[k] = (uint32_t) p;
        carry = p >> 32;
    }
    result[secp256k1_words] = carry;
    /* add the 2^32 multiple */
    result[1 + secp256k1_words] =
        vbi_add(result + 1, result + 1, right, secp256k1_words); 
}




#endif /* _UECC_CURVE_SPECIFIC_H_ */
