/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_H_
#define _UECC_H_

#include <stdint.h>

#define WORD_SIZE 4

typedef int8_t count;
typedef int16_t bits;
typedef int8_t cmp;


typedef uint32_t big;
typedef uint64_t big2;

#define HIGH_BIT_SET 0x80000000
#define WORD_BITS 32
#define WORD_BITS_SHIFT 5
#define WORD_BITS_MASK 0x01F
#define RNG_MAX_TRIES 64

#define MAX_WORDS 8

#define BITS_TO_WORDS(num_bits) ((num_bits + ((WORD_SIZE * 8) - 1)) / (WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)

#define secp256k1_bytes 32
#define secp256k1_words 8

#define BYTES_TO_WORDS_8(a, b, c, d, e, f, g, h) 0x##d##c##b##a, 0x##h##g##f##e
#define BYTES_TO_WORDS_4(a, b, c, d) 0x##d##c##b##a



struct Curve_t;
typedef const struct Curve_t * Curve;
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

Curve secp256k1(void);

typedef int (*RNG_Function)(uint8_t *dest, unsigned size);
void curve_set_rng(RNG_Function rng_function);
RNG_Function curve_get_rng(void);
static int default_RNG(uint8_t *dest, unsigned size);

int curve_private_key_size(Curve curve);
int curve_public_key_size(Curve curve);
int curve_make_key(uint8_t *public_key, uint8_t *private_key, Curve curve);
int curve_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, Curve curve);
int curve_valid_public_key(const uint8_t *public_key, Curve curve);
int curve_compute_public_key(const uint8_t *private_key, uint8_t *public_key, Curve curve);
int curve_sign(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, uint8_t *signature, Curve curve);
int curve_verify(const uint8_t *public_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *signature, Curve curve);

static void double_jacobian_secp256k1(big * X1, big * Y1, big * Z1, Curve curve);
static void x_side_secp256k1(big *result, const big *x, Curve curve);
static void vbi_mmod_fast_secp256k1(big *result, big *product);
static void omega_mult_secp256k1(big *result, const big *right);

void vbi_clear(big *vbi, count n);
big vbi_is_zero(const big *vbi, count n);
big vbi_test_bit(const big *vbi, bits bit);
static count vbi_num_digits(const big *vbi, const count max_words);
bits vbi_num_bits(const big *vbi, const count max_words);
void vbi_set(big *dest, const big *src, count n);
static cmp vbi_cmp_unsafe(const big *left, const big *right, count n);
big vbi_equal(const big *left, const big *right, count n);
big vbi_sub(big *result, const big *left, const big *right, count n);;
cmp vbi_cmp(const big *left, const big *right, count n) ;
void vbi_rshift1(big *vbi, count n);
big vbi_add(big *result, const big *left, const big *right, count n) ;
big vbi_sub(big *result, const big *left, const big *right, count n);
static void muladd(big a, big b, big *r0, big *r1, big *r2);
void vbi_mul(big *result, const big *left, const big *right, count n);
void vbi_mod_add(big *result, const big *left, const big *right, const big *mod, count n);
void vbi_mod_sub(big *result, const big *left, const big *right, const big *mod, count n);
void vbi_mmod(big *result, big *product, const big *mod, count n);
void vbi_mod_mul(big *result, const big *left, const big *right, const big *mod, count n);
void vbi_mod_mul_fast(big *result, const big *left, const big *right, Curve curve);
void vbi_mod_square_fast(big *result, const big *left, Curve curve);
static void vbi_mod_inv_update(big *uv, const big *mod, count n);
void vbi_mod_inv(big *result, const big *input, const big *mod, count n);



#endif /* _UECC_H_ */
