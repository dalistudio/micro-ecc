#include "bigint.h"

// 01.大整数清理
void vbi_clear(big *vbi, count n) {
    count i;
    for (i = 0; i < n; ++i) {
        vbi[i] = 0;
    }
}

// 02.大整数是否为零
big vbi_is_zero(const big *vbi, count n) {
    big bits = 0;
    count i;
    for (i = 0; i < n; ++i) {
        bits |= vbi[i];
    }
    return (bits == 0);
}

// 03.大整数比特位测试
big vbi_test_bit(const big *vbi, bits bit) {
    return (vbi[bit >> WORD_BITS_SHIFT] & ((big)1 << (bit & WORD_BITS_MASK)));
}

// 04.大整数的字位数
static count vbi_num_digits(const big *vbi, const count max_words) {
    count i;
    for (i = max_words - 1; i >= 0 && vbi[i] == 0; --i) {
    }

    return (i + 1);
}

// 05.大整数的比特位数
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

// 06.大整数复制
void vbi_set(big *dest, const big *src, count n) {
    count i;
    for (i = 0; i < n; ++i) {
        dest[i] = src[i];
    }
}

// 07.判断大整数是否等于
big vbi_equal(const big *left, const big *right, count n) {
    big diff = 0;
    count i;
    for (i = n - 1; i >= 0; --i) {
        diff |= (left[i] ^ right[i]);
    }
    return (diff == 0);
}

// 08.不安全的大整数比较
cmp vbi_cmp_unsafe(const big *left, const big *right, count n) {
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

// 09.大整数比较
cmp vbi_cmp(const big *left, const big *right, count n) {
    big tmp[MAX_WORDS];
    big neg = !!vbi_sub(tmp, left, right, n);
    big equal = vbi_is_zero(tmp, n);
    return (!equal - 2 * neg);
}

// 10.大整数右移1位
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

// 11.大整数加法
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

// 12.大整数减法
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

// 13.大整数乘加
static void muladd(big a, big b, big *r0, big *r1, big *r2) {
    big2 p = (big2)a * b;
    big2 r01 = ((big2)(*r1) << WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> WORD_BITS;
    *r0 = (big)r01;
}

// 14.大整数乘法
void vbi_mul(big *result, const big *left, const big *right, count n) {
    big r0 = 0;
    big r1 = 0;
    big r2 = 0;
    count i, k;

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

// 15.大整数相加求模
void vbi_mod_add(big *result, const big *left, const big *right, const big *mod, count n) {
    big carry = vbi_add(result, left, right, n);
    if (carry || vbi_cmp_unsafe(mod, result, n) != 1) {
        vbi_sub(result, result, mod, n);
    }
}

// 16.大整数相减求模
void vbi_mod_sub(big *result, const big *left, const big *right, const big *mod, count n) {
    big l_borrow = vbi_sub(result, left, right, n);
    if (l_borrow) {
        vbi_add(result, result, mod, n);
    }
}

// 17.大整数求模
void vbi_mmod(big *result, big *product, const big *mod, count n) {
    big mod_multiple[2 * MAX_WORDS];
    big tmp[2 * MAX_WORDS];
    big *v[2] = {tmp, product};
    big index;

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
        index = !(index ^ borrow);
        vbi_rshift1(mod_multiple, n);
        mod_multiple[n - 1] |= mod_multiple[n] << (WORD_BITS - 1);
        vbi_rshift1(mod_multiple + n, n);
    }
    vbi_set(result, v[index], n);
}

// 18.大整数相乘求模
void vbi_mod_mul(big *result, const big *left, const big *right, const big *mod, count n) {
    big product[2 * MAX_WORDS];
    vbi_mul(product, left, right, n);
    vbi_mmod(result, product, mod, n);
}

#define EVEN(vbi) (!(vbi[0] & 1))
// 19.大整数取反求模更新
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

// 20.大整数取反求模
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

// 21.原生格式的整数 转为 大端字节数组
void vbi_native_bytes(uint8_t *bytes, int num_bytes, const big *native) {
    int i;
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        bytes[i] = native[b / WORD_SIZE] >> (8 * (b % WORD_SIZE));
    }
}

// 22.大端字节数组 转为 原生格式的整数
void vbi_bytes_native(big *native, const uint8_t *bytes, int num_bytes) {
    int i;
    vbi_clear(native, (num_bytes + (WORD_SIZE - 1)) / WORD_SIZE);
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        native[b / WORD_SIZE] |=
            (big)bytes[i] << (8 * (b % WORD_SIZE));
    }
}