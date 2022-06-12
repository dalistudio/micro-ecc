/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _CURVE_H_
#define _CURVE_H_

#include <stdint.h>

typedef int8_t count;
typedef int16_t bits;
typedef int8_t cmp;
typedef uint32_t big;
typedef uint64_t big2;

#define MAX_WORDS 8
#define WORD_SIZE 4
#define HIGH_BIT_SET 0x80000000
#define WORD_BITS 32
#define WORD_BITS_SHIFT 5
#define WORD_BITS_MASK 0x01F
#define RNG_MAX_TRIES 64

#define BITS_TO_WORDS(num_bits) ((num_bits + ((WORD_SIZE * 8) - 1)) / (WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)
#define BYTES_TO_WORDS_8(a, b, c, d, e, f, g, h) 0x##d##c##b##a, 0x##h##g##f##e
#define BYTES_TO_WORDS_4(a, b, c, d) 0x##d##c##b##a

#define secp256k1_bytes 32
#define secp256k1_words 8

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

// 随机数的函数指针
typedef int (*RNG_Function)(uint8_t *dest, unsigned size);

// 01.生成随机整数
int generate_random_int(big *random, const big *top, count n);

// 02.设置随机数
void curve_set_rng(RNG_Function rng_function);

// 03.获得随机数
RNG_Function curve_get_rng(void);

// 04.默认随机数
static int default_RNG(uint8_t *dest, unsigned size);



// 01.生成密钥对
int curve_make_key(uint8_t *public_key, uint8_t *private_key, Curve curve);

// 02.获得私有密钥大小
int curve_private_key_size(Curve curve);

// 03.获得公有密钥大小
int curve_public_key_size(Curve curve);

// 04.生成共享密钥
int curve_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, Curve curve);

// 05.验证公钥是否有效
int curve_valid_public_key(const uint8_t *public_key, Curve curve);

// 06.根据私钥计算公钥
int curve_compute_public_key(const uint8_t *private_key, uint8_t *public_key, Curve curve);

// 07.数字签名
int curve_sign(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, uint8_t *signature, Curve curve);

// 08.验证签名
int curve_verify(const uint8_t *public_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *signature, Curve curve);


// 01.获得曲线参数
Curve secp256k1(void);

// 02.双雅可比函数
static void double_jacobian_secp256k1(big * X1, big * Y1, big * Z1, Curve curve);

// 03.
static void x_side_secp256k1(big *result, const big *x, Curve curve);

// 04.
static void vbi_mmod_fast_secp256k1(big *result, big *product);

// 05.
static void omega_mult_secp256k1(big *result, const big *right);

// 06.曲线点乘
static void EccPoint_mult(big * result, const big * point, const big * scalar, const big * initial_Z, bits num_bits, Curve curve);

// 07.曲线点公钥计算
static big EccPoint_compute_public_key(big *result, big *private_key, Curve curve);

// 08.曲线点有效验证
int curve_valid_point(const big *point, Curve curve);

// 23.曲线大整数相乘求模
void vbi_mod_mul_fast(big *result, const big *left, const big *right, Curve curve);

// 24.曲线大整数平方求模
void vbi_mod_square_fast(big *result, const big *left, Curve curve);



#endif /* _CURVE_H_ */
