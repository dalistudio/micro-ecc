#ifndef _BIGINT_H_
#define _BIGINT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
cmp vbi_cmp_unsafe(const big *left, const big *right, count n);

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

// 21.原生格式的整数 转为 大端字节数组
void vbi_native_bytes(uint8_t *bytes, int num_bytes, const big *native);

// 22.大端字节数组 转为 原生格式的整数
void vbi_bytes_native(big *native, const uint8_t *bytes, int num_bytes);


#endif /* _BIGINT_H_ */