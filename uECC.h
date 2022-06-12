/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_H_
#define _UECC_H_

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



// 01.大整数清理
void vbi_clear(big *vbi, count n);

// 02.大整数是否为零
big vbi_is_zero(const big *vbi, count n);

// 03.大整数比特位测试
big vbi_test_bit(const big *vbi, bits bit);

// 04.大整数的字位数
static count vbi_num_digits(const big *vbi, const count max_words);

// 05.大整数的比特位数
bits vbi_num_bits(const big *vbi, const count max_words);

// 06.大整数复制
void vbi_set(big *dest, const big *src, count n);

// 07.判断大整数是否等于
big vbi_equal(const big *left, const big *right, count n);

// 08.不安全的大整数比较
static cmp vbi_cmp_unsafe(const big *left, const big *right, count n);

// 09.大整数比较
cmp vbi_cmp(const big *left, const big *right, count n);

// 10.大整数右移1位
void vbi_rshift1(big *vbi, count n);

// 11.大整数加法
big vbi_add(big *result, const big *left, const big *right, count n);

// 12.大整数减法
big vbi_sub(big *result, const big *left, const big *right, count n);

// 13.大整数乘加
static void muladd(big a, big b, big *r0, big *r1, big *r2);

// 14.大整数乘法
void vbi_mul(big *result, const big *left, const big *right, count n);

// 15.大整数相加求模
void vbi_mod_add(big *result, const big *left, const big *right, const big *mod, count n);

// 16.大整数相减求模
void vbi_mod_sub(big *result, const big *left, const big *right, const big *mod, count n);

// 17.大整数求模
void vbi_mmod(big *result, big *product, const big *mod, count n);

// 18.大整数相乘求模
void vbi_mod_mul(big *result, const big *left, const big *right, const big *mod, count n);

// 19.大整数取反求模更新
static void vbi_mod_inv_update(big *uv, const big *mod, count n);

// 20.大整数取反求模
void vbi_mod_inv(big *result, const big *input, const big *mod, count n);

// 21.曲线大整数相乘求模
void vbi_mod_mul_fast(big *result, const big *left, const big *right, Curve curve);

// 22.曲线大整数平方求模
void vbi_mod_square_fast(big *result, const big *left, Curve curve);



#endif /* _UECC_H_ */
