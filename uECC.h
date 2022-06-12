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

struct Curve_t;
typedef const struct Curve_t * Curve;

Curve secp256k1(void);


/* RNG_Function type
RNG函数应该将“size”随机字节填充到“dest”中。如果“dest”中填充了随机数据，则返回1；
如果无法生成随机数据，则返回0。填写的值应该是真正随机的，或者来自加密安全的PRNG。

在调用curve_make_key()或curve_sign()之前，必须设置正常运行的RNG函数（使用curve_set_rng() ）。

设置功能正常的RNG函数可以提高curve_shared_secret()和curve_sign_deterministic()对侧通道攻击的抵抗力。
*/
typedef int (*RNG_Function)(uint8_t *dest, unsigned size);

/* 01、curve_set_rng() function.
设置将用于生成随机字节的函数。如果生成了随机数据，RNG函数应返回1；如果无法生成随机数据，RNG函数应返回0。
在没有预定义RNG函数的平台上（例如嵌入式平台），必须在使用curve_make_key()或curve_sign()之前调用该函数。

Inputs:
    rng_function - 用于生成随机字节的函数。
*/
void curve_set_rng(RNG_Function rng_function);

/* 02、curve_get_rng() function.
生成将用于生成随机返回的函数字节。
*/
RNG_Function curve_get_rng(void);

/* 03、curve_private_key_size() function.
返回曲线的私钥大小（字节）
*/
int curve_private_key_size(Curve curve);

/* 04、curve_public_key_size() function.
返回曲线的公钥大小（字节）
*/
int curve_public_key_size(Curve curve);

/* 05、curve_make_key() function.
创建公钥/私钥的密钥对

Outputs:
    public_key  - 将用公钥填充。长度必须至少为曲线大小（字节）的2倍。例如，如果曲线为secp256r1，则公钥必须为64字节长。
    private_key - 将用私钥填充。必须与曲线的顺序一样长；除secp160r1外，这通常与曲线大小相同。例如，如果曲线是secp256r1，则私钥的长度必须为32字节。

Returns 1 if the key pair was generated successfully, 0 if an error occurred.
*/
int curve_make_key(uint8_t *public_key, uint8_t *private_key, Curve curve);

/* 06、curve_shared_secret() function.
根据您的密钥和其他人的公钥计算共享密钥。如果公钥不是来自受信任的来源，并且之前未经验证，则应首先使用curve_valid_public_key() 进行验证。
注意：建议在将curve_shared_secret() 的结果用于对称加密或HMAC之前对其进行散列。

Inputs:
    public_key  - 对方的公钥
    private_key - 你的私钥

Outputs:
    secret - 将用共享秘密值填充。必须与曲线大小相同；例如，如果曲线为secp256r1，则secret的长度必须为32字节。

如果成功生成共享密钥，则返回1；如果发生错误，则返回0。
*/
int curve_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret, Curve curve);


/* 09、curve_valid_public_key() function.
检查公钥是否有效。

请注意，在使用任何其他uECC功能之前，不需要检查有效的公钥。但是，您可能希望避免花费CPU时间计算共享密钥或使用无效公钥验证签名。

Inputs:
    public_key - 要检查的公钥。

如果公钥有效，则返回1；如果公钥无效，则返回0。
*/
int curve_valid_public_key(const uint8_t *public_key, Curve curve);

/* 10、curve_compute_public_key() function.
为私钥计算相应的公钥。

Inputs:
    private_key - 为其计算公钥的私钥

Outputs:
    public_key - 将填充相应的公钥

如果密钥计算成功，则返回1；如果发生错误，则返回0。
*/
int curve_compute_public_key(const uint8_t *private_key, uint8_t *public_key, Curve curve);

/* 11、curve_sign() function.
为给定哈希值生成ECDSA签名。

用法：计算要签名的数据的散列（建议使用SHA-2），并将其与私钥一起传递到此函数。

Inputs:
    private_key  - 你的私钥。
    message_hash - 要签名的消息的散列。
    hash_size    - message_hash的大小（字节）

Outputs:
    signature - 将用签名值填充。曲线长度必须至少为2*。例如，如果曲线为secp256r1，则签名长度必须为64字节。

如果成功生成签名，则返回1；如果发生错误，则返回0。
*/
int curve_sign(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, uint8_t *signature, Curve curve);

/* 13、curve_verify() function.
验证ECDSA签名。

用法：使用与签名者相同的散列计算签名数据的散列，并将其与签名者的公钥和签名值（r和s）一起传递给此函数。

Inputs:
    public_key   - 签名者的公钥。
    message_hash - 签名数据的散列。
    hash_size    - message_hash的大小（字节）
    signature    - 签名值。

如果签名有效，则返回1；如果签名无效，则返回0。
*/
int curve_verify(const uint8_t *public_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *signature, Curve curve);

#endif /* _UECC_H_ */
