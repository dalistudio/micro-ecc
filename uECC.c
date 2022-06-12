/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#define RNG_MAX_TRIES 64

#define MAX_WORDS 8

#define BITS_TO_WORDS(num_bits) ((num_bits + ((WORD_SIZE * 8) - 1)) / (WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)

/* 兼容 POSIX 系统 */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

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

struct Curve_t {
    count word;
    count byte;
    bits bit;
    big p[MAX_WORDS];
    big n[MAX_WORDS];
    big g[MAX_WORDS * 2];
    big b[MAX_WORDS];
    void (*double_jacobian)(big * X1, big * Y1, big * Z1, Curve curve);
    void (*x_side)(big *result, const big *x, Curve curve);
    void (*mmod_fast)(big *result, big *product);
};

static cmp vbi_cmp_unsafe(const big *left, const big *right, count n);
static RNG_Function g_rng_function = &default_RNG;
void curve_set_rng(RNG_Function rng_function) {
    g_rng_function = rng_function;
}

RNG_Function curve_get_rng(void) {
    return g_rng_function;
}

int curve_private_key_size(Curve curve) {
    return BITS_TO_BYTES(curve->bit);
}

int curve_public_key_size(Curve curve) {
    return 2 * curve->byte;
}

void vbi_clear(big *vbi, count n) {
    count i;
    for (i = 0; i < n; ++i) {
        vbi[i] = 0;
    }
}

/* Constant-time comparison to zero - secure way to compare long integers */
/* Returns 1 if vbi == 0, 0 otherwise. */
/* 是否为零 */
big vbi_is_zero(const big *vbi, count n) {
    big bits = 0;
    count i;
    for (i = 0; i < n; ++i) {
        bits |= vbi[i];
    }
    return (bits == 0);
}

/* 测试比特位 */
/* Returns nonzero if bit 'bit' of vbi is set. */
big vbi_test_bit(const big *vbi, bits bit) {
    return (vbi[bit >> WORD_BITS_SHIFT] & ((big)1 << (bit & WORD_BITS_MASK)));
}

/* Counts the number of words in vbi. */
static count vbi_num_digits(const big *vbi, const count max_words) {
    count i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = max_words - 1; i >= 0 && vbi[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent vbi. */
bits vbi_num_bits(const big *vbi, const count max_words) {
    big i;
    big digit;

    count num_digits = vbi_num_digits(vbi, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vbi[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 1;
    }

    return (((bits)(num_digits - 1) << WORD_BITS_SHIFT) + i);
}

/* Sets dest = src. */
/* 大整数赋值 */
void vbi_set(big *dest, const big *src, count n) {
    count i;
    for (i = 0; i < n; ++i) {
        dest[i] = src[i];
    }
}

/* Returns sign of left - right. */
/* 不安全比较 */
static cmp vbi_cmp_unsafe(const big *left, const big *right, count n) {
    count i;
    for (i = n - 1; i >= 0; --i) {
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
big vbi_equal(const big *left, const big *right, count n) {
    big diff = 0;
    count i;
    for (i = n - 1; i >= 0; --i) {
        diff |= (left[i] ^ right[i]);
    }
    return (diff == 0);
}

big vbi_sub(big *result, const big *left, const big *right, count n);

/* Returns sign of left - right, in constant time. */
/* 比较 */
cmp vbi_cmp(const big *left, const big *right, count n) {
    big tmp[MAX_WORDS];
    big neg = !!vbi_sub(tmp, left, right, n);
    big equal = vbi_is_zero(tmp, n);
    return (!equal - 2 * neg);
}

/* Computes vbi = vbi >> 1. */
/* 右移1位 */
#if !asm_rshift1
void vbi_rshift1(big *vbi, count n) {
    big *end = vbi;
    big carry = 0;

    vbi += n;
    while (vbi-- > end) {
        big temp = *vbi;
        *vbi = (temp >> 1) | carry;
        carry = temp << (WORD_BITS - 1);
    }
}
#endif /* !asm_rshift1 */

/* Computes result = left + right, returning carry. Can modify in place. */
/* 加法 */
#if !asm_add
big vbi_add(big *result, const big *left, const big *right, count n) {
    big carry = 0; /* 进位 */
    count i;
    for (i = 0; i < n; ++i) {
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
big vbi_sub(big *result, const big *left, const big *right, count n) {
    big borrow = 0; /* 借位 */
    count i;
    for (i = 0; i < n; ++i) {
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
void vbi_mul(big *result, const big *left, const big *right, count n) {
    big r0 = 0;
    big r1 = 0;
    big r2 = 0;
    count i, k;

    /* Compute each digit of result in sequence, maintaining the carries. */
    for (k = 0; k < n; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = n; k < n * 2 - 1; ++k) {
        for (i = (k + 1) - n; i < n; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[n * 2 - 1] = r0;
}
#endif /* !asm_mult */

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
/* 相加求模 */
void vbi_mod_add(big *result, const big *left, const big *right, const big *mod, count n) {
    big carry = vbi_add(result, left, right, n);
    if (carry || vbi_cmp_unsafe(mod, result, n) != 1) {
        /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
        vbi_sub(result, result, mod, n);
    }
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
/* 相减求模 */
void vbi_mod_sub(big *result, const big *left, const big *right, const big *mod, count n) {
    big l_borrow = vbi_sub(result, left, right, n);
    if (l_borrow) {
        /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
           we can get the correct result from result + mod (with overflow). */
        vbi_add(result, result, mod, n);
    }
}

/* Computes result = product % mod, where product is 2N words long. */
/* Currently only designed to work for curve_p or curve_n. */
/* 求模 */
void vbi_mmod(big *result, big *product, const big *mod, count n) {
    big mod_multiple[2 * MAX_WORDS];
    big tmp[2 * MAX_WORDS];
    big *v[2] = {tmp, product};
    big index;

    /* Shift mod so its highest set bit is at the maximum position. */
    bits shift = (n * 2 * WORD_BITS) - vbi_num_bits(mod, n);
    count word_shift = shift / WORD_BITS;
    count bit_shift = shift % WORD_BITS;
    big carry = 0;
    vbi_clear(mod_multiple, word_shift);
    if (bit_shift > 0) {
        for(index = 0; index < (big)n; ++index) {
            mod_multiple[word_shift + index] = (mod[index] << bit_shift) | carry;
            carry = mod[index] >> (WORD_BITS - bit_shift);
        }
    } else {
        vbi_set(mod_multiple + word_shift, mod, n);
    }

    for (index = 1; shift >= 0; --shift) {
        big borrow = 0;
        count i;
        for (i = 0; i < n * 2; ++i) {
            big diff = v[index][i] - mod_multiple[i] - borrow;
            if (diff != v[index][i]) {
                borrow = (diff > v[index][i]);
            }
            v[1 - index][i] = diff;
        }
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        vbi_rshift1(mod_multiple, n);
        mod_multiple[n - 1] |= mod_multiple[n] << (WORD_BITS - 1);
        vbi_rshift1(mod_multiple + n, n);
    }
    vbi_set(result, v[index], n);
}

/* Computes result = (left * right) % mod. */
/* 相乘求模 */
void vbi_mod_mul(big *result, const big *left, const big *right, const big *mod, count n) {
    big product[2 * MAX_WORDS];
    vbi_mul(product, left, right, n);
    vbi_mmod(result, product, mod, n);
}

/* 曲线相乘求模 */
void vbi_mod_mul_fast(big *result, const big *left, const big *right, Curve curve) {
    big product[2 * MAX_WORDS];
    vbi_mul(product, left, right, curve->word);

    curve->mmod_fast(result, product);

}

/* 曲线平方求模 */
void vbi_mod_square_fast(big *result, const big *left, Curve curve) {
    vbi_mod_mul_fast(result, left, left, curve);
}



/* 取反求模 更新 */
#define EVEN(vbi) (!(vbi[0] & 1))
static void vbi_mod_inv_update(big *uv, const big *mod, count n) {
    big carry = 0;
    if (!EVEN(uv)) {
        carry = vbi_add(uv, uv, mod, n);
    }
    vbi_rshift1(uv, n);
    if (carry) {
        uv[n - 1] |= HIGH_BIT_SET;
    }
}

/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide" */
/* 取反求模 */
void vbi_mod_inv(big *result, const big *input, const big *mod, count n) {
    big a[MAX_WORDS], b[MAX_WORDS], u[MAX_WORDS], v[MAX_WORDS];
    cmp cmpResult;

    if (vbi_is_zero(input, n)) {
        vbi_clear(result, n);
        return;
    }

    vbi_set(a, input, n);
    vbi_set(b, mod, n);
    vbi_clear(u, n);
    u[0] = 1;
    vbi_clear(v, n);
    while ((cmpResult = vbi_cmp_unsafe(a, b, n)) != 0) {
        if (EVEN(a)) {
            vbi_rshift1(a, n);
            vbi_mod_inv_update(u, mod, n);
        } else if (EVEN(b)) {
            vbi_rshift1(b, n);
            vbi_mod_inv_update(v, mod, n);
        } else if (cmpResult > 0) {
            vbi_sub(a, a, b, n);
            vbi_rshift1(a, n);
            if (vbi_cmp_unsafe(u, v, n) < 0) {
                vbi_add(u, u, mod, n);
            }
            vbi_sub(u, u, v, n);
            vbi_mod_inv_update(u, mod, n);
        } else {
            vbi_sub(b, b, a, n);
            vbi_rshift1(b, n);
            if (vbi_cmp_unsafe(v, u, n) < 0) {
                vbi_add(v, v, mod, n);
            }
            vbi_sub(v, v, u, n);
            vbi_mod_inv_update(v, mod, n);
        }
    }
    vbi_set(result, u, n);
}

/* ------ Point operations ------ */
/* ------ 点操作 ------*/

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

Curve secp256k1(void) { return &curve_secp256k1; }

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


/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point, curve) vbi_is_zero((point), (curve)->word * 2)

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

/* result may overlap point. */
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

/* Generates a random integer in the range 0 < random < top.
   Both random and top have n words. */
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


void vbi_native_bytes(uint8_t *bytes, int num_bytes, const big *native) {
    int i;
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        bytes[i] = native[b / WORD_SIZE] >> (8 * (b % WORD_SIZE));
    }
}

void vbi_bytes_native(big *native, const uint8_t *bytes, int num_bytes) {
    int i;
    vbi_clear(native, (num_bytes + (WORD_SIZE - 1)) / WORD_SIZE);
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        native[b / WORD_SIZE] |=
            (big)bytes[i] << (8 * (b % WORD_SIZE));
    }
}



/* 生成公钥和私钥 */
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

/* 共享密钥 */
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


    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(_private, _private, tmp, curve);

    /* If an RNG function was specified, try to get a random initial Z value to improve
       protection against side-channel attacks. */
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

/* 有效的点 */
int uECC_valid_point(const big *point, Curve curve) {
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

/* 有效的公钥 */
int curve_valid_public_key(const uint8_t *public_key, Curve curve) {

    big _public[MAX_WORDS * 2];



    vbi_bytes_native(_public, public_key, curve->byte);
    vbi_bytes_native(
        _public + curve->word, public_key + curve->byte, curve->byte);

    return uECC_valid_point(_public, curve);
}

/* 计算公钥 */
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

/* 比特转整数 */
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

/* 用内部k签名 */
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

/* For testing - sign with an explicitly specified k value */
/* 用k签名 */
int curve_sign_with_k(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *k, uint8_t *signature, Curve curve) {
    big k2[MAX_WORDS];
    bits2int(k2, k, BITS_TO_BYTES(curve->bit), curve);
    return curve_sign_with_k_internal(private_key, message_hash, hash_size, k2, signature, curve);
}

/* 签名 */
int curve_sign(const uint8_t *private_key,
              const uint8_t *message_hash,
              unsigned hash_size,
              uint8_t *signature,
              Curve curve) {
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

/* 验证 */
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

