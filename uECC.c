/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "types.h"

#define RNG_MAX_TRIES 64
#define vbi_API static

#include "platform-specific.h"

#define MAX_WORDS 8

#define BITS_TO_WORDS(num_bits) ((num_bits + ((WORD_SIZE * 8) - 1)) / (WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)

struct Curve_t {
    count num_words;
    count num_bytes;
    bits num_n_bits;
    big p[MAX_WORDS];
    big n[MAX_WORDS];
    big G[MAX_WORDS * 2];
    big b[MAX_WORDS];
    void (*double_jacobian)(big * X1, big * Y1, big * Z1, Curve curve);
    void (*x_side)(big *result, const big *x, Curve curve);
    void (*mmod_fast)(big *result, big *product);
};

static cmp vbi_cmp_unsafe(const big *left, const big *right, count num_words);
static RNG_Function g_rng_function = &default_RNG;
void uECC_set_rng(RNG_Function rng_function) {
    g_rng_function = rng_function;
}

RNG_Function uECC_get_rng(void) {
    return g_rng_function;
}

int uECC_curve_private_key_size(Curve curve) {
    return BITS_TO_BYTES(curve->num_n_bits);
}

int uECC_curve_public_key_size(Curve curve) {
    return 2 * curve->num_bytes;
}

#if !asm_clear
vbi_API void vbi_clear(big *vli, count num_words) {
    count i;
    for (i = 0; i < num_words; ++i) {
        vli[i] = 0;
    }
}
#endif /* !asm_clear */

/* Constant-time comparison to zero - secure way to compare long integers */
/* Returns 1 if vli == 0, 0 otherwise. */
/* 是否为零 */
vbi_API big vbi_is_zero(const big *vli, count num_words) {
    big bits = 0;
    count i;
    for (i = 0; i < num_words; ++i) {
        bits |= vli[i];
    }
    return (bits == 0);
}

/* 测试比特位 */
/* Returns nonzero if bit 'bit' of vli is set. */
vbi_API big vbi_test_bit(const big *vli, bits bit) {
    return (vli[bit >> WORD_BITS_SHIFT] & ((big)1 << (bit & WORD_BITS_MASK)));
}

/* Counts the number of words in vli. */
static count vli_num_digits(const big *vli, const count max_words) {
    count i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = max_words - 1; i >= 0 && vli[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent vli. */
vbi_API bits vbi_num_bits(const big *vli, const count max_words) {
    big i;
    big digit;

    count num_digits = vli_num_digits(vli, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vli[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 1;
    }

    return (((bits)(num_digits - 1) << WORD_BITS_SHIFT) + i);
}

/* Sets dest = src. */
/* 大整数赋值 */
#if !asm_set
vbi_API void vbi_set(big *dest, const big *src, count num_words) {
    count i;
    for (i = 0; i < num_words; ++i) {
        dest[i] = src[i];
    }
}
#endif /* !asm_set */

/* Returns sign of left - right. */
/* 不安全比较 */
static cmp vbi_cmp_unsafe(const big *left, const big *right, count num_words) {
    count i;
    for (i = num_words - 1; i >= 0; --i) {
        if (left[i] > right[i]) {
            return 1;
        } else if (left[i] < right[i]) {
            return -1;
        }
    }
    return 0;
}

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise. */
/* 等于 */
vbi_API big vbi_equal(const big *left, const big *right, count num_words) {
    big diff = 0;
    count i;
    for (i = num_words - 1; i >= 0; --i) {
        diff |= (left[i] ^ right[i]);
    }
    return (diff == 0);
}

vbi_API big vbi_sub(big *result, const big *left, const big *right, count num_words);

/* Returns sign of left - right, in constant time. */
/* 比较 */
vbi_API cmp vbi_cmp(const big *left, const big *right, count num_words) {
    big tmp[MAX_WORDS];
    big neg = !!vbi_sub(tmp, left, right, num_words);
    big equal = vbi_is_zero(tmp, num_words);
    return (!equal - 2 * neg);
}

/* Computes vli = vli >> 1. */
/* 右移1位 */
#if !asm_rshift1
vbi_API void vbi_rshift1(big *vli, count num_words) {
    big *end = vli;
    big carry = 0;

    vli += num_words;
    while (vli-- > end) {
        big temp = *vli;
        *vli = (temp >> 1) | carry;
        carry = temp << (WORD_BITS - 1);
    }
}
#endif /* !asm_rshift1 */

/* Computes result = left + right, returning carry. Can modify in place. */
/* 加法 */
#if !asm_add
vbi_API big vbi_add(big *result, const big *left, const big *right, count num_words) {
    big carry = 0; /* 进位 */
    count i;
    for (i = 0; i < num_words; ++i) {
        big sum = left[i] + right[i] + carry;
        if (sum != left[i]) {
            carry = (sum < left[i]); // 如果  sum < left[i]成立，返回1,否则返回0
        }
        result[i] = sum;
    }
    return carry;
}
#endif /* !asm_add */

/* Computes result = left - right, returning borrow. Can modify in place. */
/* 减法 */
#if !asm_sub
vbi_API big vbi_sub(big *result, const big *left, const big *right, count num_words) {
    big borrow = 0; /* 借位 */
    count i;
    for (i = 0; i < num_words; ++i) {
        big diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}
#endif /* !asm_sub */

/* 乘加 */
static void muladd(big a, big b, big *r0, big *r1, big *r2) {

    big2 p = (big2)a * b;
    big2 r01 = ((big2)(*r1) << WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> WORD_BITS;
    *r0 = (big)r01;

}

/* 乘法 */
#if !asm_mult
vbi_API void vbi_mul(big *result, const big *left, const big *right, count num_words) {
    big r0 = 0;
    big r1 = 0;
    big r2 = 0;
    count i, k;

    /* Compute each digit of result in sequence, maintaining the carries. */
    for (k = 0; k < num_words; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = num_words; k < num_words * 2 - 1; ++k) {
        for (i = (k + 1) - num_words; i < num_words; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[num_words * 2 - 1] = r0;
}
#endif /* !asm_mult */

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
/* 相加求模 */
vbi_API void vbi_mod_add(big *result, const big *left, const big *right, const big *mod, count num_words) {
    big carry = vbi_add(result, left, right, num_words);
    if (carry || vbi_cmp_unsafe(mod, result, num_words) != 1) {
        /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
        vbi_sub(result, result, mod, num_words);
    }
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
/* 相减求模 */
vbi_API void vbi_mod_sub(big *result, const big *left, const big *right, const big *mod, count num_words) {
    big l_borrow = vbi_sub(result, left, right, num_words);
    if (l_borrow) {
        /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
           we can get the correct result from result + mod (with overflow). */
        vbi_add(result, result, mod, num_words);
    }
}

/* Computes result = product % mod, where product is 2N words long. */
/* Currently only designed to work for curve_p or curve_n. */
/* 求模 */
vbi_API void vbi_mmod(big *result, big *product, const big *mod, count num_words) {
    big mod_multiple[2 * MAX_WORDS];
    big tmp[2 * MAX_WORDS];
    big *v[2] = {tmp, product};
    big index;

    /* Shift mod so its highest set bit is at the maximum position. */
    bits shift = (num_words * 2 * WORD_BITS) - vbi_num_bits(mod, num_words);
    count word_shift = shift / WORD_BITS;
    count bit_shift = shift % WORD_BITS;
    big carry = 0;
    vbi_clear(mod_multiple, word_shift);
    if (bit_shift > 0) {
        for(index = 0; index < (big)num_words; ++index) {
            mod_multiple[word_shift + index] = (mod[index] << bit_shift) | carry;
            carry = mod[index] >> (WORD_BITS - bit_shift);
        }
    } else {
        vbi_set(mod_multiple + word_shift, mod, num_words);
    }

    for (index = 1; shift >= 0; --shift) {
        big borrow = 0;
        count i;
        for (i = 0; i < num_words * 2; ++i) {
            big diff = v[index][i] - mod_multiple[i] - borrow;
            if (diff != v[index][i]) {
                borrow = (diff > v[index][i]);
            }
            v[1 - index][i] = diff;
        }
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        vbi_rshift1(mod_multiple, num_words);
        mod_multiple[num_words - 1] |= mod_multiple[num_words] << (WORD_BITS - 1);
        vbi_rshift1(mod_multiple + num_words, num_words);
    }
    vbi_set(result, v[index], num_words);
}

/* Computes result = (left * right) % mod. */
/* 相乘求模 */
vbi_API void vbi_mod_mul(big *result, const big *left, const big *right, const big *mod, count num_words) {
    big product[2 * MAX_WORDS];
    vbi_mul(product, left, right, num_words);
    vbi_mmod(result, product, mod, num_words);
}

/* 曲线相乘求模 */
vbi_API void vbi_mod_mul_fast(big *result, const big *left, const big *right, Curve curve) {
    big product[2 * MAX_WORDS];
    vbi_mul(product, left, right, curve->num_words);

    curve->mmod_fast(result, product);

}

/* 曲线平方求模 */
vbi_API void vbi_mod_square_fast(big *result, const big *left, Curve curve) {
    vbi_mod_mul_fast(result, left, left, curve);
}



/* 取反求模 更新 */
#define EVEN(vli) (!(vli[0] & 1))
static void vbi_mod_inv_update(big *uv, const big *mod, count num_words) {
    big carry = 0;
    if (!EVEN(uv)) {
        carry = vbi_add(uv, uv, mod, num_words);
    }
    vbi_rshift1(uv, num_words);
    if (carry) {
        uv[num_words - 1] |= HIGH_BIT_SET;
    }
}

/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide" */
/* 取反求模 */
vbi_API void vbi_mod_inv(big *result, const big *input, const big *mod, count num_words) {
    big a[MAX_WORDS], b[MAX_WORDS], u[MAX_WORDS], v[MAX_WORDS];
    cmp cmpResult;

    if (vbi_is_zero(input, num_words)) {
        vbi_clear(result, num_words);
        return;
    }

    vbi_set(a, input, num_words);
    vbi_set(b, mod, num_words);
    vbi_clear(u, num_words);
    u[0] = 1;
    vbi_clear(v, num_words);
    while ((cmpResult = vbi_cmp_unsafe(a, b, num_words)) != 0) {
        if (EVEN(a)) {
            vbi_rshift1(a, num_words);
            vbi_mod_inv_update(u, mod, num_words);
        } else if (EVEN(b)) {
            vbi_rshift1(b, num_words);
            vbi_mod_inv_update(v, mod, num_words);
        } else if (cmpResult > 0) {
            vbi_sub(a, a, b, num_words);
            vbi_rshift1(a, num_words);
            if (vbi_cmp_unsafe(u, v, num_words) < 0) {
                vbi_add(u, u, mod, num_words);
            }
            vbi_sub(u, u, v, num_words);
            vbi_mod_inv_update(u, mod, num_words);
        } else {
            vbi_sub(b, b, a, num_words);
            vbi_rshift1(b, num_words);
            if (vbi_cmp_unsafe(v, u, num_words) < 0) {
                vbi_add(v, v, mod, num_words);
            }
            vbi_sub(v, v, u, num_words);
            vbi_mod_inv_update(v, mod, num_words);
        }
    }
    vbi_set(result, u, num_words);
}

/* ------ Point operations ------ */
/* ------ 点操作 ------*/

#include "curve-specific.h"

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) vbi_is_zero((point), (curve)->num_words * 2)

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
   点乘算法使用 co-Z坐标的蒙哥马利阶梯
From http://eprint.iacr.org/2011/338.pdf
*/

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(big * X1,
                    big * Y1,
                    const big * const Z,
                    Curve curve) {
    big t1[MAX_WORDS];

    vbi_mod_square_fast(t1, Z, curve);    /* z^2 */
    vbi_mod_mul_fast(X1, X1, t1, curve); /* x1 * z^2 */
    vbi_mod_mul_fast(t1, t1, Z, curve);  /* z^3 */
    vbi_mod_mul_fast(Y1, Y1, t1, curve); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(big * X1, big * Y1, big * X2, big * Y2, const big * const initial_Z, Curve curve) {
    big z[MAX_WORDS];
    count num_words = curve->num_words;
    if (initial_Z) {
        vbi_set(z, initial_Z, num_words);
    } else {
        vbi_clear(z, num_words);
        z[0] = 1;
    }

    vbi_set(X2, X1, num_words);
    vbi_set(Y2, Y1, num_words);

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
    count num_words = curve->num_words;

    vbi_mod_sub(t5, X2, X1, curve->p, num_words); /* t5 = x2 - x1 */
    vbi_mod_square_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
    vbi_mod_mul_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
    vbi_mod_mul_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y2 - y1 */
    vbi_mod_square_fast(t5, Y2, curve);                  /* t5 = (y2 - y1)^2 = D */

    vbi_mod_sub(t5, t5, X1, curve->p, num_words); /* t5 = D - B */
    vbi_mod_sub(t5, t5, X2, curve->p, num_words); /* t5 = D - B - C = x3 */
    vbi_mod_sub(X2, X2, X1, curve->p, num_words); /* t3 = C - B */
    vbi_mod_mul_fast(Y1, Y1, X2, curve);                /* t2 = y1*(C - B) */
    vbi_mod_sub(X2, X1, t5, curve->p, num_words); /* t3 = B - x3 */
    vbi_mod_mul_fast(Y2, Y2, X2, curve);                /* t4 = (y2 - y1)*(B - x3) */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y3 */

    vbi_set(X2, t5, num_words);
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
    count num_words = curve->num_words;

    vbi_mod_sub(t5, X2, X1, curve->p, num_words); /* t5 = x2 - x1 */
    vbi_mod_square_fast(t5, t5, curve);                  /* t5 = (x2 - x1)^2 = A */
    vbi_mod_mul_fast(X1, X1, t5, curve);                /* t1 = x1*A = B */
    vbi_mod_mul_fast(X2, X2, t5, curve);                /* t3 = x2*A = C */
    vbi_mod_add(t5, Y2, Y1, curve->p, num_words); /* t5 = y2 + y1 */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, num_words); /* t4 = y2 - y1 */

    vbi_mod_sub(t6, X2, X1, curve->p, num_words); /* t6 = C - B */
    vbi_mod_mul_fast(Y1, Y1, t6, curve);                /* t2 = y1 * (C - B) = E */
    vbi_mod_add(t6, X1, X2, curve->p, num_words); /* t6 = B + C */
    vbi_mod_square_fast(X2, Y2, curve);                  /* t3 = (y2 - y1)^2 = D */
    vbi_mod_sub(X2, X2, t6, curve->p, num_words); /* t3 = D - (B + C) = x3 */

    vbi_mod_sub(t7, X1, X2, curve->p, num_words); /* t7 = B - x3 */
    vbi_mod_mul_fast(Y2, Y2, t7, curve);                /* t4 = (y2 - y1)*(B - x3) */
    vbi_mod_sub(Y2, Y2, Y1, curve->p, num_words); /* t4 = (y2 - y1)*(B - x3) - E = y3 */

    vbi_mod_square_fast(t7, t5, curve);                  /* t7 = (y2 + y1)^2 = F */
    vbi_mod_sub(t7, t7, t6, curve->p, num_words); /* t7 = F - (B + C) = x3' */
    vbi_mod_sub(t6, t7, X1, curve->p, num_words); /* t6 = x3' - B */
    vbi_mod_mul_fast(t6, t6, t5, curve);                /* t6 = (y2+y1)*(x3' - B) */
    vbi_mod_sub(Y1, t6, Y1, curve->p, num_words); /* t2 = (y2+y1)*(x3' - B) - E = y3' */

    vbi_set(X1, t7, num_words);
}

/* result may overlap point. */
static void EccPoint_mult(big * result, const big * point, const big * scalar, const big * initial_Z, bits num_bits, Curve curve) {
    /* R0 and R1 */
    big Rx[2][MAX_WORDS];
    big Ry[2][MAX_WORDS];
    big z[MAX_WORDS];
    bits i;
    big nb;
    count num_words = curve->num_words;

    vbi_set(Rx[1], point, num_words);
    vbi_set(Ry[1], point + num_words, num_words);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z, curve);

    for (i = num_bits - 2; i > 0; --i) {
        nb = !vbi_test_bit(scalar, i);
        XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
    }

    nb = !vbi_test_bit(scalar, 0);
    XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb], curve);

    /* Find final 1/Z value. */
    vbi_mod_sub(z, Rx[1], Rx[0], curve->p, num_words); /* X1 - X0 */
    vbi_mod_mul_fast(z, z, Ry[1 - nb], curve);               /* Yb * (X1 - X0) */
    vbi_mod_mul_fast(z, z, point, curve);                    /* xP * Yb * (X1 - X0) */
    vbi_mod_inv(z, z, curve->p, num_words);            /* 1 / (xP * Yb * (X1 - X0)) */
    /* yP / (xP * Yb * (X1 - X0)) */
    vbi_mod_mul_fast(z, z, point + num_words, curve);
    vbi_mod_mul_fast(z, z, Rx[1 - nb], curve); /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb], curve);
    apply_z(Rx[0], Ry[0], z, curve);

    vbi_set(result, Rx[0], num_words);
    vbi_set(result + num_words, Ry[0], num_words);
}

static big regularize_k(const big * const k, big *k0, big *k1, Curve curve) {
    count num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    bits num_n_bits = curve->num_n_bits;
    big carry = vbi_add(k0, k, curve->n, num_n_words) ||
        (num_n_bits < ((bits)num_n_words * WORD_SIZE * 8) &&
         vbi_test_bit(k0, num_n_bits));
    vbi_add(k1, k0, curve->n, num_n_words);
    return carry;
}

/* Generates a random integer in the range 0 < random < top.
   Both random and top have num_words words. */
vbi_API int uECC_generate_random_int(big *random, const big *top, count num_words) {
    big mask = (big)-1;
    big tries;
    bits num_bits = vbi_num_bits(top, num_words);

    if (!g_rng_function) {
        return 0;
    }

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        if (!g_rng_function((uint8_t *)random, num_words * WORD_SIZE)) {
            return 0;
        }
        random[num_words - 1] &= mask >> ((bits)(num_words * WORD_SIZE * 8 - num_bits));
        if (!vbi_is_zero(random, num_words) &&
                vbi_cmp(top, random, num_words) == 1) {
            return 1;
        }
    }
    return 0;
}

static big EccPoint_compute_public_key(big *result, big *private_key, Curve curve) {
    big tmp1[MAX_WORDS];
    big tmp2[MAX_WORDS];
    big *p2[2] = {tmp1, tmp2};
    big *initial_Z = 0;
    big carry;

    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(private_key, tmp1, tmp2, curve);

    /* If an RNG function was specified, try to get a random initial Z value to improve
       protection against side-channel attacks. */
    if (g_rng_function) {
        if (!uECC_generate_random_int(p2[carry], curve->p, curve->num_words)) {
            return 0;
        }
        initial_Z = p2[carry];
    }
    EccPoint_mult(result, curve->G, p2[!carry], initial_Z, curve->num_n_bits + 1, curve);

    if (EccPoint_isZero(result, curve)) {
        return 0;
    }
    return 1;
}


vbi_API void vbi_native_bytes(uint8_t *bytes, int num_bytes, const big *native) {
    int i;
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        bytes[i] = native[b / WORD_SIZE] >> (8 * (b % WORD_SIZE));
    }
}

vbi_API void vbi_bytes_native(big *native, const uint8_t *bytes, int num_bytes) {
    int i;
    vbi_clear(native, (num_bytes + (WORD_SIZE - 1)) / WORD_SIZE);
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        native[b / WORD_SIZE] |=
            (big)bytes[i] << (8 * (b % WORD_SIZE));
    }
}



/* 生成公钥和私钥 */
int uECC_make_key(uint8_t *public_key, uint8_t *private_key, Curve curve) {

    big _private[MAX_WORDS];
    big _public[MAX_WORDS * 2];

    big tries;

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        if (!uECC_generate_random_int(_private, curve->n, BITS_TO_WORDS(curve->num_n_bits))) {
            return 0;
        }

        if (EccPoint_compute_public_key(_public, _private, curve)) {

            vbi_native_bytes(private_key, BITS_TO_BYTES(curve->num_n_bits), _private);
            vbi_native_bytes(public_key, curve->num_bytes, _public);
            vbi_native_bytes(
                public_key + curve->num_bytes, curve->num_bytes, _public + curve->num_words);

            return 1;
        }
    }
    return 0;
}

/* 共享密钥 */
int uECC_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, Curve curve) {
    big _public[MAX_WORDS * 2];
    big _private[MAX_WORDS];

    big tmp[MAX_WORDS];
    big *p2[2] = {_private, tmp};
    big *initial_Z = 0;
    big carry;
    count num_words = curve->num_words;
    count num_bytes = curve->num_bytes;


    vbi_bytes_native(_private, private_key, BITS_TO_BYTES(curve->num_n_bits));
    vbi_bytes_native(_public, public_key, num_bytes);
    vbi_bytes_native(_public + num_words, public_key + num_bytes, num_bytes);


    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(_private, _private, tmp, curve);

    /* If an RNG function was specified, try to get a random initial Z value to improve
       protection against side-channel attacks. */
    if (g_rng_function) {
        if (!uECC_generate_random_int(p2[carry], curve->p, num_words)) {
            return 0;
        }
        initial_Z = p2[carry];
    }

    EccPoint_mult(_public, _public, p2[!carry], initial_Z, curve->num_n_bits + 1, curve);

    vbi_native_bytes(secret, num_bytes, _public);

    return !EccPoint_isZero(_public, curve);
}

/* 有效的点 */
vbi_API int uECC_valid_point(const big *point, Curve curve) {
    big tmp1[MAX_WORDS];
    big tmp2[MAX_WORDS];
    count num_words = curve->num_words;

    /* The point at infinity is invalid. */
    if (EccPoint_isZero(point, curve)) {
        return 0;
    }

    /* x and y must be smaller than p. */
    if (vbi_cmp_unsafe(curve->p, point, num_words) != 1 ||
            vbi_cmp_unsafe(curve->p, point + num_words, num_words) != 1) {
        return 0;
    }

    vbi_mod_square_fast(tmp1, point + num_words, curve);
    curve->x_side(tmp2, point, curve); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    return (int)(vbi_equal(tmp1, tmp2, num_words));
}

/* 有效的公钥 */
int uECC_valid_public_key(const uint8_t *public_key, Curve curve) {

    big _public[MAX_WORDS * 2];



    vbi_bytes_native(_public, public_key, curve->num_bytes);
    vbi_bytes_native(
        _public + curve->num_words, public_key + curve->num_bytes, curve->num_bytes);

    return uECC_valid_point(_public, curve);
}

/* 计算公钥 */
int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, Curve curve) {

    big _private[MAX_WORDS];
    big _public[MAX_WORDS * 2];



    vbi_bytes_native(_private, private_key, BITS_TO_BYTES(curve->num_n_bits));


    /* Make sure the private key is in the range [1, n-1]. */
    if (vbi_is_zero(_private, BITS_TO_WORDS(curve->num_n_bits))) {
        return 0;
    }

    if (vbi_cmp(curve->n, _private, BITS_TO_WORDS(curve->num_n_bits)) != 1) {
        return 0;
    }

    /* Compute public key. */
    if (!EccPoint_compute_public_key(_public, _private, curve)) {
        return 0;
    }


    vbi_native_bytes(public_key, curve->num_bytes, _public);
    vbi_native_bytes(
        public_key + curve->num_bytes, curve->num_bytes, _public + curve->num_words);

    return 1;
}


/* -------- ECDSA code -------- */

/* 比特转整数 */
static void bits2int(big *native, const uint8_t *bits, unsigned bits_size, Curve curve) {
    unsigned num_n_bytes = BITS_TO_BYTES(curve->num_n_bits);
    unsigned num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    int shift;
    big carry;
    big *ptr;

    if (bits_size > num_n_bytes) {
        bits_size = num_n_bytes;
    }

    vbi_clear(native, num_n_words);

    vbi_bytes_native(native, bits, bits_size);

    if (bits_size * 8 <= (unsigned)curve->num_n_bits) {
        return;
    }
    shift = bits_size * 8 - curve->num_n_bits;
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

/* 用内部k签名 */
static int uECC_sign_with_k_internal(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, big *k, uint8_t *signature, Curve curve) {

    big tmp[MAX_WORDS];
    big s[MAX_WORDS];
    big *k2[2] = {tmp, s};
    big *initial_Z = 0;

    big p[MAX_WORDS * 2];

    big carry;
    count num_words = curve->num_words;
    count num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    bits num_n_bits = curve->num_n_bits;

    /* Make sure 0 < k < curve_n */
    if (vbi_is_zero(k, num_words) || vbi_cmp(curve->n, k, num_n_words) != 1) {
        return 0;
    }

    carry = regularize_k(k, tmp, s, curve);
    /* If an RNG function was specified, try to get a random initial Z value to improve
       protection against side-channel attacks. */
    if (g_rng_function) {
        if (!uECC_generate_random_int(k2[carry], curve->p, num_words)) {
            return 0;
        }
        initial_Z = k2[carry];
    }
    EccPoint_mult(p, curve->G, k2[!carry], initial_Z, num_n_bits + 1, curve);
    if (vbi_is_zero(p, num_words)) {
        return 0;
    }

    /* If an RNG function was specified, get a random number
       to prevent side channel analysis of k. */
    if (!g_rng_function) {
        vbi_clear(tmp, num_n_words);
        tmp[0] = 1;
    } else if (!uECC_generate_random_int(tmp, curve->n, num_n_words)) {
        return 0;
    }

    /* Prevent side channel analysis of vbi_mod_inv() to determine
       bits of k / the private key by premultiplying by a random number */
    vbi_mod_mul(k, k, tmp, curve->n, num_n_words); /* k' = rand * k */
    vbi_mod_inv(k, k, curve->n, num_n_words);       /* k = 1 / k' */
    vbi_mod_mul(k, k, tmp, curve->n, num_n_words); /* k = 1 / k */


    vbi_native_bytes(signature, curve->num_bytes, p); /* store r */

    vbi_bytes_native(tmp, private_key, BITS_TO_BYTES(curve->num_n_bits)); /* tmp = d */


    s[num_n_words - 1] = 0;
    vbi_set(s, p, num_words);
    vbi_mod_mul(s, tmp, s, curve->n, num_n_words); /* s = r*d */

    bits2int(tmp, message_hash, hash_size, curve);
    vbi_mod_add(s, tmp, s, curve->n, num_n_words); /* s = e + r*d */
    vbi_mod_mul(s, s, k, curve->n, num_n_words);  /* s = (e + r*d) / k */
    if (vbi_num_bits(s, num_n_words) > (bits)curve->num_bytes * 8) {
        return 0;
    }

    vbi_native_bytes(signature + curve->num_bytes, curve->num_bytes, s);

    return 1;
}

/* For testing - sign with an explicitly specified k value */
/* 用k签名 */
int uECC_sign_with_k(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *k, uint8_t *signature, Curve curve) {
    big k2[MAX_WORDS];
    bits2int(k2, k, BITS_TO_BYTES(curve->num_n_bits), curve);
    return uECC_sign_with_k_internal(private_key, message_hash, hash_size, k2, signature, curve);
}

/* 签名 */
int uECC_sign(const uint8_t *private_key,
              const uint8_t *message_hash,
              unsigned hash_size,
              uint8_t *signature,
              Curve curve) {
    big k[MAX_WORDS];
    big tries;

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        if (!uECC_generate_random_int(k, curve->n, BITS_TO_WORDS(curve->num_n_bits))) {
            return 0;
        }

        if (uECC_sign_with_k_internal(private_key, message_hash, hash_size, k, signature, curve)) {
            return 1;
        }
    }
    return 0;
}

/* Compute an HMAC using K as a key (as in RFC 6979). Note that K is always
   the same size as the hash result size. */
/* HMAC散列算法 */
static void HMAC_init(const uECC_HashContext *hash_context, const uint8_t *K) {
    uint8_t *pad = hash_context->tmp + 2 * hash_context->result_size;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i)
        pad[i] = K[i] ^ 0x36;
    for (; i < hash_context->block_size; ++i)
        pad[i] = 0x36;

    hash_context->init_hash(hash_context);
    hash_context->update_hash(hash_context, pad, hash_context->block_size);
}

static void HMAC_update(const uECC_HashContext *hash_context, const uint8_t *message, unsigned message_size) {
    hash_context->update_hash(hash_context, message, message_size);
}

static void HMAC_finish(const uECC_HashContext *hash_context, const uint8_t *K, uint8_t *result) {
    uint8_t *pad = hash_context->tmp + 2 * hash_context->result_size;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i)
        pad[i] = K[i] ^ 0x5c;
    for (; i < hash_context->block_size; ++i)
        pad[i] = 0x5c;

    hash_context->finish_hash(hash_context, result);

    hash_context->init_hash(hash_context);
    hash_context->update_hash(hash_context, pad, hash_context->block_size);
    hash_context->update_hash(hash_context, result, hash_context->result_size);
    hash_context->finish_hash(hash_context, result);
}

/* V = HMAC_K(V) */
static void update_V(const uECC_HashContext *hash_context, uint8_t *K, uint8_t *V) {
    HMAC_init(hash_context, K);
    HMAC_update(hash_context, V, hash_context->result_size);
    HMAC_finish(hash_context, K, V);
}

/* Deterministic signing, similar to RFC 6979. Differences are:
    * We just use H(m) directly rather than bits2octets(H(m))
      (it is not reduced modulo curve_n).
    * We generate a value for k (aka T) directly rather than converting endianness.

   Layout of hash_context->tmp: <K> | <V> | (1 byte overlapped 0x00 or 0x01) / <HMAC pad> */
/* 确定性签名 */
int uECC_sign_deterministic(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, const uECC_HashContext *hash_context, uint8_t *signature, Curve curve) {
    uint8_t *K = hash_context->tmp;
    uint8_t *V = K + hash_context->result_size;
    count num_bytes = curve->num_bytes;
    count num_n_words = BITS_TO_WORDS(curve->num_n_bits);
    bits num_n_bits = curve->num_n_bits;
    big tries;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i) {
        V[i] = 0x01;
        K[i] = 0;
    }

    /* K = HMAC_K(V || 0x00 || int2octets(x) || h(m)) */
    HMAC_init(hash_context, K);
    V[hash_context->result_size] = 0x00;
    HMAC_update(hash_context, V, hash_context->result_size + 1);
    HMAC_update(hash_context, private_key, num_bytes);
    HMAC_update(hash_context, message_hash, hash_size);
    HMAC_finish(hash_context, K, K);

    update_V(hash_context, K, V);

    /* K = HMAC_K(V || 0x01 || int2octets(x) || h(m)) */
    HMAC_init(hash_context, K);
    V[hash_context->result_size] = 0x01;
    HMAC_update(hash_context, V, hash_context->result_size + 1);
    HMAC_update(hash_context, private_key, num_bytes);
    HMAC_update(hash_context, message_hash, hash_size);
    HMAC_finish(hash_context, K, K);

    update_V(hash_context, K, V);

    for (tries = 0; tries < RNG_MAX_TRIES; ++tries) {
        big T[MAX_WORDS];
        uint8_t *T_ptr = (uint8_t *)T;
        count T_bytes = 0;
        for (;;) {
            update_V(hash_context, K, V);
            for (i = 0; i < hash_context->result_size; ++i) {
                T_ptr[T_bytes++] = V[i];
                if (T_bytes >= num_n_words * WORD_SIZE) {
                    goto filled;
                }
            }
        }
    filled:
        if ((bits)num_n_words * WORD_SIZE * 8 > num_n_bits) {
            big mask = (big)-1;
            T[num_n_words - 1] &=
                mask >> ((bits)(num_n_words * WORD_SIZE * 8 - num_n_bits));
        }

        if (uECC_sign_with_k_internal(private_key, message_hash, hash_size, T, signature, curve)) {
            return 1;
        }

        /* K = HMAC_K(V || 0x00) */
        HMAC_init(hash_context, K);
        V[hash_context->result_size] = 0x00;
        HMAC_update(hash_context, V, hash_context->result_size + 1);
        HMAC_finish(hash_context, K, K);

        update_V(hash_context, K, V);
    }
    return 0;
}

static bits smax(bits a, bits b) {
    return (a > b ? a : b);
}

/* 验证 */
int uECC_verify(const uint8_t *public_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *signature, Curve curve) {
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
    count num_words = curve->num_words;
    count num_n_words = BITS_TO_WORDS(curve->num_n_bits);

    rx[num_n_words - 1] = 0;
    r[num_n_words - 1] = 0;
    s[num_n_words - 1] = 0;


    vbi_bytes_native(_public, public_key, curve->num_bytes);
    vbi_bytes_native(
        _public + num_words, public_key + curve->num_bytes, curve->num_bytes);
    vbi_bytes_native(r, signature, curve->num_bytes);
    vbi_bytes_native(s, signature + curve->num_bytes, curve->num_bytes);


    /* r, s must not be 0. */
    if (vbi_is_zero(r, num_words) || vbi_is_zero(s, num_words)) {
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
    vbi_set(sum, _public, num_words);
    vbi_set(sum + num_words, _public + num_words, num_words);
    vbi_set(tx, curve->G, num_words);
    vbi_set(ty, curve->G + num_words, num_words);
    vbi_mod_sub(z, sum, tx, curve->p, num_words); /* z = x2 - x1 */
    XYcZ_add(tx, ty, sum, sum + num_words, curve);
    vbi_mod_inv(z, z, curve->p, num_words); /* z = 1/z */
    apply_z(sum, sum + num_words, z, curve);

    /* Use Shamir's trick to calculate u1*G + u2*Q */
    points[0] = 0;
    points[1] = curve->G;
    points[2] = _public;
    points[3] = sum;
    num_bits = smax(vbi_num_bits(u1, num_n_words),
                    vbi_num_bits(u2, num_n_words));

    point = points[(!!vbi_test_bit(u1, num_bits - 1)) |
                   ((!!vbi_test_bit(u2, num_bits - 1)) << 1)];
    vbi_set(rx, point, num_words);
    vbi_set(ry, point + num_words, num_words);
    vbi_clear(z, num_words);
    z[0] = 1;

    for (i = num_bits - 2; i >= 0; --i) {
        big index;
        curve->double_jacobian(rx, ry, z, curve);

        index = (!!vbi_test_bit(u1, i)) | ((!!vbi_test_bit(u2, i)) << 1);
        point = points[index];
        if (point) {
            vbi_set(tx, point, num_words);
            vbi_set(ty, point + num_words, num_words);
            apply_z(tx, ty, z, curve);
            vbi_mod_sub(tz, rx, tx, curve->p, num_words); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry, curve);
            vbi_mod_mul_fast(z, z, tz, curve);
        }
    }

    vbi_mod_inv(z, z, curve->p, num_words); /* Z = 1/Z */
    apply_z(rx, ry, z, curve);

    /* v = x1 (mod n) */
    if (vbi_cmp_unsafe(curve->n, rx, num_n_words) != 1) {
        vbi_sub(rx, rx, curve->n, num_n_words);
    }

    /* Accept only if v == r. */
    return (int)(vbi_equal(rx, r, num_words));
}

