/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "curve.h"
#include "bigint.h"

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

// 04.默认随机数
static int default_RNG(uint8_t *dest, unsigned size) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            return 0;
        }
    }
    
    char *ptr = (char *)dest;
    size_t left = size;
    while (left > 0) {
        ssize_t bytes_read = read(fd, ptr, left);
        if (bytes_read <= 0) { // read failed
            close(fd);
            return 0;
        }
        left -= bytes_read;
        ptr += bytes_read;
    }
    
    close(fd);
    return 1;
}

static RNG_Function g_rng_function = &default_RNG;

// 02.设置随机数
void curve_set_rng(RNG_Function rng_function) {
    g_rng_function = rng_function;
}

// 03.获得随机数
RNG_Function curve_get_rng(void) {
    return g_rng_function;
}

// 02.获得私有密钥大小
int curve_private_key_size(Curve curve) {
    return BITS_TO_BYTES(curve->bit);
}

// 03.获得公有密钥大小
int curve_public_key_size(Curve curve) {
    return 2 * curve->byte;
}



// 23.曲线大整数相乘求模
void vbi_mod_mul_fast(big *result, const big *left, const big *right, Curve curve) {
    big product[2 * MAX_WORDS];
    vbi_mul(product, left, right, curve->word);

    curve->mmod_fast(result, product);

}

// 24.曲线大整数平方求模
void vbi_mod_square_fast(big *result, const big *left, Curve curve) {
    vbi_mod_mul_fast(result, left, left, curve);
}


/* ------ Point operations ------ */
static const struct Curve_t curve_secp256k1 = {
    secp256k1_words,
    secp256k1_bytes,
    256,
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

// 01.获得曲线参数
Curve secp256k1(void) { return &curve_secp256k1; }

// 02.双雅可比函数
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

// 03.
/* Computes result = x^3 + b. result must not overlap x. */
static void x_side_secp256k1(big *result, const big *x, Curve curve) {
    vbi_mod_square_fast(result, x, curve);                                /* r = x^2 */
    vbi_mod_mul_fast(result, result, x, curve);                          /* r = x^3 */
    vbi_mod_add(result, result, curve->b, curve->p, secp256k1_words); /* r = x^3 + b */
}

// 04.
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

// 05.
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


/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) vbi_is_zero((point), (curve)->word * 2)

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
   点乘算法使用 co-Z坐标的蒙哥马利阶梯
From http://eprint.iacr.org/2011/338.pdf
*/

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(big * X1, big * Y1, const big * const Z, Curve curve) {
    big t1[MAX_WORDS];

    vbi_mod_square_fast(t1, Z, curve);    /* z^2 */
    vbi_mod_mul_fast(X1, X1, t1, curve); /* x1 * z^2 */
    vbi_mod_mul_fast(t1, t1, Z, curve);  /* z^3 */
    vbi_mod_mul_fast(Y1, Y1, t1, curve); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(big * X1, big * Y1, big * X2, big * Y2, const big * const initial_Z, Curve curve) {
    big z[MAX_WORDS];
    count n = curve->word;
    if (initial_Z) {
        vbi_set(z, initial_Z, n);
    } else {
        vbi_clear(z, n);
        z[0] = 1;
    }

    vbi_set(X2, X1, n);
    vbi_set(Y2, Y1, n);

    apply_z(X1, Y1, z, curve);
    curve->double_jacobian(X1, Y1, z, curve);
    apply_z(X2, Y2, z, curve);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(big * X1, big * Y1, big * X2, big * Y2, Curve curve) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    big t5[MAX_WORDS];
    count n = curve->word;

    vbi_mod_sub(t5, X2, X1, curve->p, n); /* t5 = x2 - x1 */
    vbi_mod_square_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
    vbi_mod_mul_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
    vbi_mod_mul_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, n); /* t4 = y2 - y1 */
    vbi_mod_square_fast(t5, Y2, curve);                  /* t5 = (y2 - y1)^2 = D */

    vbi_mod_sub(t5, t5, X1, curve->p, n); /* t5 = D - B */
    vbi_mod_sub(t5, t5, X2, curve->p, n); /* t5 = D - B - C = x3 */
    vbi_mod_sub(X2, X2, X1, curve->p, n); /* t3 = C - B */
    vbi_mod_mul_fast(Y1, Y1, X2, curve);                /* t2 = y1*(C - B) */
    vbi_mod_sub(X2, X1, t5, curve->p, n); /* t3 = B - x3 */
    vbi_mod_mul_fast(Y2, Y2, X2, curve);                /* t4 = (y2 - y1)*(B - x3) */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, n); /* t4 = y3 */

    vbi_set(X2, t5, n);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(big * X1, big * Y1, big * X2, big * Y2, Curve curve) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    big t5[MAX_WORDS];
    big t6[MAX_WORDS];
    big t7[MAX_WORDS];
    count n = curve->word;

    vbi_mod_sub(t5, X2, X1, curve->p, n); /* t5 = x2 - x1 */
    vbi_mod_square_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
    vbi_mod_mul_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
    vbi_mod_mul_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
    vbi_mod_add(t5, Y2, Y1, curve->p, n); /* t5 = y2 + y1 */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, n); /* t4 = y2 - y1 */

    vbi_mod_sub(t6, X2, X1, curve->p, n); /* t6 = C - B */
    vbi_mod_mul_fast(Y1, Y1, t6, curve);                /* t2 = y1 * (C - B) = E */
    vbi_mod_add(t6, X1, X2, curve->p, n); /* t6 = B + C */
    vbi_mod_square_fast(X2, Y2, curve);                  /* t3 = (y2 - y1)^2 = D */
    vbi_mod_sub(X2, X2, t6, curve->p, n); /* t3 = D - (B + C) = x3 */

    vbi_mod_sub(t7, X1, X2, curve->p, n); /* t7 = B - x3 */
    vbi_mod_mul_fast(Y2, Y2, t7, curve);                /* t4 = (y2 - y1)*(B - x3) */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, n); /* t4 = (y2 - y1)*(B - x3) - E = y3 */

    vbi_mod_square_fast(t7, t5, curve);                  /* t7 = (y2 + y1)^2 = F */
    vbi_mod_sub(t7, t7, t6, curve->p, n); /* t7 = F - (B + C) = x3' */
    vbi_mod_sub(t6, t7, X1, curve->p, n); /* t6 = x3' - B */
    vbi_mod_mul_fast(t6, t6, t5, curve);                /* t6 = (y2+y1)*(x3' - B) */
    vbi_mod_sub(Y1, t6, Y1, curve->p, n); /* t2 = (y2+y1)*(x3' - B) - E = y3' */

    vbi_set(X1, t7, n);
}

// 06.曲线点乘
static void EccPoint_mult(big * result, const big * point, const big * scalar, const big * initial_Z, bits num_bits, Curve curve) {
    /* R0 and R1 */
    big Rx[2][MAX_WORDS];
    big Ry[2][MAX_WORDS];
    big z[MAX_WORDS];
    bits i;
    big nb;
    count n = curve->word;

    vbi_set(Rx[1], point, n);
    vbi_set(Ry[1], point + n, n);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z, curve);

    for (i = num_bits - 2; i > 0; --i) {
        nb = !vbi_test_bit(scalar, i);
        XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
    }

    nb = !vbi_test_bit(scalar, 0);
    XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);

    /* Find final 1/Z value. */
    vbi_mod_sub(z, Rx[1], Rx[0], curve->p, n); /* X1 - X0 */
    vbi_mod_mul_fast(z, z, Ry[1 - nb], curve);               /* Yb * (X1 - X0) */
    vbi_mod_mul_fast(z, z, point, curve);                    /* xP * Yb * (X1 - X0) */
    vbi_mod_inv(z, z, curve->p, n);            /* 1 / (xP * Yb * (X1 - X0)) */
    /* yP / (xP * Yb * (X1 - X0)) */
    vbi_mod_mul_fast(z, z, point + n, curve);
    vbi_mod_mul_fast(z, z, Rx[1 - nb], curve); /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
    apply_z(Rx[0], Ry[0], z, curve);

    vbi_set(result, Rx[0], n);
    vbi_set(result + n, Ry[0], n);
}

static big regularize_k(const big * const k, big *k0, big *k1, Curve curve) {
    count num_n_words = BITS_TO_WORDS(curve->bit);
    bits num_n_bits = curve->bit;
    big carry = vbi_add(k0, k, curve->n, num_n_words) ||
        (num_n_bits < ((bits)num_n_words * WORD_SIZE * 8) &&
         vbi_test_bit(k0, num_n_bits));
    vbi_add(k1, k0, curve->n, num_n_words);
    return carry;
}

// 01.生成随机整数
int generate_random_int(big *random, const big *top, count n) {
    big mask = (big)-1;
    big tries;
    bits num_bits = vbi_num_bits(top, n);

    if (!g_rng_function) {
        return 0;
    }

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        if (!g_rng_function((uint8_t *)random, n * WORD_SIZE)) {
            return 0;
        }
        random[n - 1] &= mask >> ((bits)(n * WORD_SIZE * 8 - num_bits));
        if (!vbi_is_zero(random, n) &&
                vbi_cmp(top, random, n) == 1) {
            return 1;
        }
    }
    return 0;
}

// 07.曲线点公钥计算
static big EccPoint_compute_public_key(big *result, big *private_key, Curve curve) {
    big tmp1[MAX_WORDS];
    big tmp2[MAX_WORDS];
    big *p2[2] = {tmp1, tmp2};
    big *initial_Z = 0;
    big carry;

    carry = regularize_k(private_key, tmp1, tmp2, curve);

    if (g_rng_function) {
        if (!generate_random_int(p2[carry], curve->p, curve->word)) {
            return 0;
        }
        initial_Z = p2[carry];
    }
    EccPoint_mult(result, curve->g, p2[!carry], initial_Z, curve->bit + 1, curve);

    if (EccPoint_isZero(result, curve)) {
        return 0;
    }
    return 1;
}


// 01.生成密钥对
int curve_make_key(uint8_t *public_key, uint8_t *private_key, Curve curve) {

    big _private[MAX_WORDS];
    big _public[MAX_WORDS * 2];

    big tries;

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        if (!generate_random_int(_private, curve->n, BITS_TO_WORDS(curve->bit))) {
            return 0;
        }

        if (EccPoint_compute_public_key(_public, _private, curve)) {

            vbi_native_bytes(private_key, BITS_TO_BYTES(curve->bit), _private);
            vbi_native_bytes(public_key, curve->byte, _public);
            vbi_native_bytes(
                public_key + curve->byte, curve->byte, _public + curve->word);

            return 1;
        }
    }
    return 0;
}

// 04.生成共享密钥
int curve_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, Curve curve) {
    big _public[MAX_WORDS * 2];
    big _private[MAX_WORDS];

    big tmp[MAX_WORDS];
    big *p2[2] = {_private, tmp};
    big *initial_Z = 0;
    big carry;
    count n = curve->word;
    count num_bytes = curve->byte;


    vbi_bytes_native(_private, private_key, BITS_TO_BYTES(curve->bit));
    vbi_bytes_native(_public, public_key, num_bytes);
    vbi_bytes_native(_public + n, public_key + num_bytes, num_bytes);

    carry = regularize_k(_private, _private, tmp, curve);

    if (g_rng_function) {
        if (!generate_random_int(p2[carry], curve->p, n)) {
            return 0;
        }
        initial_Z = p2[carry];
    }

    EccPoint_mult(_public, _public, p2[!carry], initial_Z, curve->bit + 1, curve);

    vbi_native_bytes(secret, num_bytes, _public);

    return !EccPoint_isZero(_public, curve);
}

// 08.曲线点有效验证
int curve_valid_point(const big *point, Curve curve) {
    big tmp1[MAX_WORDS];
    big tmp2[MAX_WORDS];
    count n = curve->word;

    /* The point at infinity is invalid. */
    if (EccPoint_isZero(point, curve)) {
        return 0;
    }

    /* x and y must be smaller than p. */
    if (vbi_cmp_unsafe(curve->p, point, n) != 1 ||
            vbi_cmp_unsafe(curve->p, point + n, n) != 1) {
        return 0;
    }

    vbi_mod_square_fast(tmp1, point + n, curve);
    curve->x_side(tmp2, point, curve); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    return (int)(vbi_equal(tmp1, tmp2, n));
}

// 05.验证公钥是否有效
int curve_valid_public_key(const uint8_t *public_key, Curve curve) {

    big _public[MAX_WORDS * 2];

    vbi_bytes_native(_public, public_key, curve->byte);
    vbi_bytes_native(
        _public + curve->word, public_key + curve->byte, curve->byte);

    return curve_valid_point(_public, curve);
}

// 06.根据私钥计算公钥
int curve_compute_public_key(const uint8_t *private_key, uint8_t *public_key, Curve curve) {

    big _private[MAX_WORDS];
    big _public[MAX_WORDS * 2];

    vbi_bytes_native(_private, private_key, BITS_TO_BYTES(curve->bit));

    /* Make sure the private key is in the range [1, n-1]. */
    if (vbi_is_zero(_private, BITS_TO_WORDS(curve->bit))) {
        return 0;
    }

    if (vbi_cmp(curve->n, _private, BITS_TO_WORDS(curve->bit)) != 1) {
        return 0;
    }

    /* Compute public key. */
    if (!EccPoint_compute_public_key(_public, _private, curve)) {
        return 0;
    }

    vbi_native_bytes(public_key, curve->byte, _public);
    vbi_native_bytes(
        public_key + curve->byte, curve->byte, _public + curve->word);

    return 1;
}


/* -------- ECDSA code -------- */

static void bits2int(big *native, const uint8_t *bits, unsigned bits_size, Curve curve) {
    unsigned num_n_bytes = BITS_TO_BYTES(curve->bit);
    unsigned num_n_words = BITS_TO_WORDS(curve->bit);
    int shift;
    big carry;
    big *ptr;

    if (bits_size > num_n_bytes) {
        bits_size = num_n_bytes;
    }

    vbi_clear(native, num_n_words);

    vbi_bytes_native(native, bits, bits_size);

    if (bits_size * 8 <= (unsigned)curve->bit) {
        return;
    }
    shift = bits_size * 8 - curve->bit;
    carry = 0;
    ptr = native + num_n_words;
    while (ptr-- > native) {
        big temp = *ptr;
        *ptr = (temp >> shift) | carry;
        carry = temp << (WORD_BITS - shift);
    }

    /* Reduce mod curve_n */
    if (vbi_cmp_unsafe(curve->n, native, num_n_words) != 1) {
        vbi_sub(native, native, curve->n, num_n_words);
    }
}

// 07.数字签名
static int curve_sign_with_k_internal(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, big *k, uint8_t *signature, Curve curve) {

    big tmp[MAX_WORDS];
    big s[MAX_WORDS];
    big *k2[2] = {tmp, s};
    big *initial_Z = 0;

    big p[MAX_WORDS * 2];

    big carry;
    count n = curve->word;
    count num_n_words = BITS_TO_WORDS(curve->bit);
    bits num_n_bits = curve->bit;

    /* Make sure 0 < k < curve_n */
    if (vbi_is_zero(k, n) || vbi_cmp(curve->n, k, num_n_words) != 1) {
        return 0;
    }

    carry = regularize_k(k, tmp, s, curve);
    /* If an RNG function was specified, try to get a random initial Z value to improve
       protection against side-channel attacks. */
    if (g_rng_function) {
        if (!generate_random_int(k2[carry], curve->p, n)) {
            return 0;
        }
        initial_Z = k2[carry];
    }
    EccPoint_mult(p, curve->g, k2[!carry], initial_Z, num_n_bits + 1, curve);
    if (vbi_is_zero(p, n)) {
        return 0;
    }

    /* If an RNG function was specified, get a random number
       to prevent side channel analysis of k. */
    if (!g_rng_function) {
        vbi_clear(tmp, num_n_words);
        tmp[0] = 1;
    } else if (!generate_random_int(tmp, curve->n, num_n_words)) {
        return 0;
    }

    /* Prevent side channel analysis of vbi_mod_inv() to determine
       bits of k / the private key by premultiplying by a random number */
    vbi_mod_mul(k, k, tmp, curve->n, num_n_words); /* k' = rand * k */
    vbi_mod_inv(k, k, curve->n, num_n_words);       /* k = 1 / k' */
    vbi_mod_mul(k, k, tmp, curve->n, num_n_words); /* k = 1 / k */


    vbi_native_bytes(signature, curve->byte, p); /* store r */

    vbi_bytes_native(tmp, private_key, BITS_TO_BYTES(curve->bit)); /* tmp = d */


    s[num_n_words - 1] = 0;
    vbi_set(s, p, n);
    vbi_mod_mul(s, tmp, s, curve->n, num_n_words); /* s = r*d */

    bits2int(tmp, message_hash, hash_size, curve);
    vbi_mod_add(s, tmp, s, curve->n, num_n_words); /* s = e + r*d */
    vbi_mod_mul(s, s, k, curve->n, num_n_words);  /* s = (e + r*d) / k */
    if (vbi_num_bits(s, num_n_words) > (bits)curve->byte * 8) {
        return 0;
    }

    vbi_native_bytes(signature + curve->byte, curve->byte, s);

    return 1;
}

int curve_sign_with_k(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *k, uint8_t *signature, Curve curve) {
    big k2[MAX_WORDS];
    bits2int(k2, k, BITS_TO_BYTES(curve->bit), curve);
    return curve_sign_with_k_internal(private_key, message_hash, hash_size, k2, signature, curve);
}

// 07.数字签名
int curve_sign(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, uint8_t *signature, Curve curve) {
    big k[MAX_WORDS];
    big tries;

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        if (!generate_random_int(k, curve->n, BITS_TO_WORDS(curve->bit))) {
            return 0;
        }

        if (curve_sign_with_k_internal(private_key, message_hash, hash_size, k, signature, curve)) {
            return 1;
        }
    }
    return 0;
}

static bits smax(bits a, bits b) {
    return (a > b ? a : b);
}

// 08.验证签名
int curve_verify(const uint8_t *public_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *signature, Curve curve) {
    big u1[MAX_WORDS], u2[MAX_WORDS];
    big z[MAX_WORDS];
    big sum[MAX_WORDS * 2];
    big rx[MAX_WORDS];
    big ry[MAX_WORDS];
    big tx[MAX_WORDS];
    big ty[MAX_WORDS];
    big tz[MAX_WORDS];
    const big *points[4];
    const big *point;
    bits num_bits;
    bits i;

    big _public[MAX_WORDS * 2];

    big r[MAX_WORDS], s[MAX_WORDS];
    count n = curve->word;
    count num_n_words = BITS_TO_WORDS(curve->bit);

    rx[num_n_words - 1] = 0;
    r[num_n_words - 1] = 0;
    s[num_n_words - 1] = 0;

    vbi_bytes_native(_public, public_key, curve->byte);
    vbi_bytes_native(_public + n, public_key + curve->byte, curve->byte);
    vbi_bytes_native(r, signature, curve->byte);
    vbi_bytes_native(s, signature + curve->byte, curve->byte);

    /* r, s must not be 0. */
    if (vbi_is_zero(r, n) || vbi_is_zero(s, n)) {
        return 0;
    }

    /* r, s must be < n. */
    if (vbi_cmp_unsafe(curve->n, r, num_n_words) != 1 ||
            vbi_cmp_unsafe(curve->n, s, num_n_words) != 1) {
        return 0;
    }

    /* Calculate u1 and u2. */
    vbi_mod_inv(z, s, curve->n, num_n_words); /* z = 1/s */
    u1[num_n_words - 1] = 0;
    bits2int(u1, message_hash, hash_size, curve);
    vbi_mod_mul(u1, u1, z, curve->n, num_n_words); /* u1 = e/s */
    vbi_mod_mul(u2, r, z, curve->n, num_n_words); /* u2 = r/s */

    /* Calculate sum = G + Q. */
    vbi_set(sum, _public, n);
    vbi_set(sum + n, _public + n, n);
    vbi_set(tx, curve->g, n);
    vbi_set(ty, curve->g + n, n);
    vbi_mod_sub(z, sum, tx, curve->p, n); /* z = x2 - x1 */
    XYcZ_add(tx, ty, sum, sum + n, curve);
    vbi_mod_inv(z, z, curve->p, n); /* z = 1/z */
    apply_z(sum, sum + n, z, curve);

    /* Use Shamir's trick to calculate u1*G + u2*Q */
    points[0] = 0;
    points[1] = curve->g;
    points[2] = _public;
    points[3] = sum;
    num_bits = smax(vbi_num_bits(u1, num_n_words),
                    vbi_num_bits(u2, num_n_words));

    point = points[(!!vbi_test_bit(u1, num_bits - 1)) |
                   ((!!vbi_test_bit(u2, num_bits - 1)) << 1)];
    vbi_set(rx, point, n);
    vbi_set(ry, point + n, n);
    vbi_clear(z, n);
    z[0] = 1;

    for (i = num_bits - 2; i >= 0; --i) {
        big index;
        curve->double_jacobian(rx, ry, z, curve);

        index = (!!vbi_test_bit(u1, i)) | ((!!vbi_test_bit(u2, i)) << 1);
        point = points[index];
        if (point) {
            vbi_set(tx, point, n);
            vbi_set(ty, point + n, n);
            apply_z(tx, ty, z, curve);
            vbi_mod_sub(tz, rx, tx, curve->p, n); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry, curve);
            vbi_mod_mul_fast(z, z, tz, curve);
        }
    }

    vbi_mod_inv(z, z, curve->p, n); /* Z = 1/Z */
    apply_z(rx, ry, z, curve);

    /* v = x1 (mod n) */
    if (vbi_cmp_unsafe(curve->n, rx, num_n_words) != 1) {
        vbi_sub(rx, rx, curve->n, num_n_words);
    }

    /* Accept only if v == r. */
    return (int)(vbi_equal(rx, r, n));
}

