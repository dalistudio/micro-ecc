/* Copyright 2015, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_TYPES_H_
#define _UECC_TYPES_H_

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

#endif /* _UECC_TYPES_H_ */
