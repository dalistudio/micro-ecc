/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_H_
#define _UECC_H_

#include <stdint.h>

/* Platform selection options. 平台的选项
If uECC_PLATFORM is not defined, the code will try to guess it based on compiler macros.
Possible values for uECC_PLATFORM are defined below: 
如果未定义uECC_PLATFORM，代码将根据编译器宏尝试猜测它。uECC_PLATFORM的可能值定义如下：
*/
#define uECC_arch_other 0 /* 其他架构 */
#define uECC_x86        1 /* X86 32位 */
#define uECC_x86_64     2 /* X86 64位 */
#define uECC_arm        3 /* ARM 32位 */
#define uECC_arm_thumb  4 /* ARM Thumb */
#define uECC_arm_thumb2 5 /* ARM Thumb2 */
#define uECC_arm64      6 /* ARM 32位 */
#define uECC_avr        7 /* AVR 8位 */

/* If desired, you can define uECC_WORD_SIZE as appropriate for your platform (1, 4, or 8 bytes).
If uECC_WORD_SIZE is not explicitly defined then it will be automatically set based on your
platform. 
如果需要，您可以根据您的平台定义 uECC_WORD_SIZE（1、4或8字节）。如果未明确定义uECC_WORD_SIZE，则会根据您的平台自动设置。
*/

/* Optimization level; trade speed for code size.
   Larger values produce code that is faster but larger.
   Currently supported values are 0 - 4; 0 is unusably slow for most applications.
   Optimization level 4 currently only has an effect ARM platforms where more than one
   curve is enabled. 
   优化水平；以速度换取代码大小。值越大，生成的代码越快但越大。当前支持的值为0-4；对于大多数应用程序来说，0的速度都非常慢。优化级别4目前仅对启用多条曲线的ARM平台有效。
*/
#ifndef uECC_OPTIMIZATION_LEVEL
    #define uECC_OPTIMIZATION_LEVEL 2
#endif

/* uECC_SQUARE_FUNC - If enabled (defined as nonzero), this will cause a specific function to be
used for (scalar) squaring instead of the generic multiplication function. This can make things
faster somewhat faster, but increases the code size. 
uECC_SQUARE_FUNC - 如果启用（定义为非零），这将导致特定函数用于（标量）平方，而不是通用乘法函数。这可以让事情变得更快，但会增加代码大小。
*/
#ifndef uECC_SQUARE_FUNC
    #define uECC_SQUARE_FUNC 0
#endif

/* uECC_VLI_NATIVE_LITTLE_ENDIAN - If enabled (defined as nonzero), this will switch to native
little-endian format for *all* arrays passed in and out of the public API. This includes public
and private keys, shared secrets, signatures and message hashes.
Using this switch reduces the amount of call stack memory used by uECC, since less intermediate
translations are required.
uECC_VLI_NATIVE_LITTLE_ENDIAN - 如果启用（定义为非零），则对于传入和传出公共API的*all*数组，这将切换为NATIVE LITTLE ENDIAN格式。
这包括公钥和私钥、共享机密、签名和消息哈希。使用此开关可以减少uECC使用的调用堆栈内存量，因为需要的中间转换更少。

Note that this will *only* work on native little-endian processors and it will treat the uint8_t
arrays passed into the public API as word arrays, therefore requiring the provided byte arrays
to be word aligned on architectures that do not support unaligned accesses.
请注意，这将*仅*在本机little endian处理器上工作，并将传递到公共API的uint8_t数组视为字数组，因此要求提供的字节数组在不支持未对齐访问的体系结构上进行字对齐。

IMPORTANT: Keys and signatures generated with uECC_VLI_NATIVE_LITTLE_ENDIAN=1 are incompatible
with keys and signatures generated with uECC_VLI_NATIVE_LITTLE_ENDIAN=0; all parties must use
the same endianness. 
重要提示：uECC_VLI_NATIVE_LITTLE_ENDIAN=1生成的密钥和签名与uECC_VLI_NATIVE_LITTLE_ENDIAN=0生成的密钥和签名不兼容；各方都必须使用相同的结束语。
*/
#ifndef uECC_VLI_NATIVE_LITTLE_ENDIAN
    #define uECC_VLI_NATIVE_LITTLE_ENDIAN 0
#endif

/* Curve support selection. Set to 0 to remove that curve. 
曲线支撑选择。设置为0以删除该曲线。
*/
#ifndef uECC_SUPPORTS_secp160r1
    #define uECC_SUPPORTS_secp160r1 1
#endif
#ifndef uECC_SUPPORTS_secp192r1
    #define uECC_SUPPORTS_secp192r1 1
#endif
#ifndef uECC_SUPPORTS_secp224r1
    #define uECC_SUPPORTS_secp224r1 1
#endif
#ifndef uECC_SUPPORTS_secp256r1
    #define uECC_SUPPORTS_secp256r1 1
#endif
#ifndef uECC_SUPPORTS_secp256k1
    #define uECC_SUPPORTS_secp256k1 1
#endif

/* Specifies whether compressed point format is supported.
   Set to 0 to disable point compression/decompression functions. 

指定是否支持压缩点格式。
设置为0可禁用点压缩/解压缩功能。   
*/
#ifndef uECC_SUPPORT_COMPRESSED_POINT
    #define uECC_SUPPORT_COMPRESSED_POINT 1
#endif

struct uECC_Curve_t;
typedef const struct uECC_Curve_t * uECC_Curve;

#ifdef __cplusplus
extern "C"
{
#endif

#if uECC_SUPPORTS_secp160r1
uECC_Curve uECC_secp160r1(void);
#endif
#if uECC_SUPPORTS_secp192r1
uECC_Curve uECC_secp192r1(void);
#endif
#if uECC_SUPPORTS_secp224r1
uECC_Curve uECC_secp224r1(void);
#endif
#if uECC_SUPPORTS_secp256r1
uECC_Curve uECC_secp256r1(void);
#endif
#if uECC_SUPPORTS_secp256k1
uECC_Curve uECC_secp256k1(void);
#endif

/* uECC_RNG_Function type
The RNG function should fill 'size' random bytes into 'dest'. It should return 1 if
'dest' was filled with random data, or 0 if the random data could not be generated.
The filled-in values should be either truly random, or from a cryptographically-secure PRNG.
RNG函数应该将“size”随机字节填充到“dest”中。如果“dest”中填充了随机数据，则返回1；
如果无法生成随机数据，则返回0。填写的值应该是真正随机的，或者来自加密安全的PRNG。

A correctly functioning RNG function must be set (using uECC_set_rng()) before calling
uECC_make_key() or uECC_sign().
在调用uECC_make_key()或uECC_sign()之前，必须设置正常运行的RNG函数（使用uECC_set_rng() ）。

Setting a correctly functioning RNG function improves the resistance to side-channel attacks
for uECC_shared_secret() and uECC_sign_deterministic().
设置功能正常的RNG函数可以提高uECC_shared_secret()和uECC_sign_deterministic()对侧通道攻击的抵抗力。


A correct RNG function is set by default when building for Windows, Linux, or OS X.
If you are building on another POSIX-compliant system that supports /dev/random or /dev/urandom,
you can define uECC_POSIX to use the predefined RNG. For embedded platforms there is no predefined
RNG function; you must provide your own.
在为Windows、Linux或OS X构建时，默认情况下会设置正确的RNG函数。如果您在另一个支持/dev/random或/dev/uradom的POSIX兼容系统上构建，
则可以定义uECC_POSIX以使用预定义的RNG。对于嵌入式平台，没有预定义的RNG功能；你必须提供你自己的。
*/
typedef int (*uECC_RNG_Function)(uint8_t *dest, unsigned size);

/* 01、uECC_set_rng() function.

Set the function that will be used to generate random bytes. The RNG function should
return 1 if the random data was generated, or 0 if the random data could not be generated.
设置将用于生成随机字节的函数。如果生成了随机数据，RNG函数应返回1；如果无法生成随机数据，RNG函数应返回0。

On platforms where there is no predefined RNG function (eg embedded platforms), this must
be called before uECC_make_key() or uECC_sign() are used.
在没有预定义RNG函数的平台上（例如嵌入式平台），必须在使用uECC_make_key()或uECC_sign()之前调用该函数。

Inputs:
    rng_function - The function that will be used to generate random bytes. 用于生成随机字节的函数。
*/
void uECC_set_rng(uECC_RNG_Function rng_function);

/* 02、uECC_get_rng() function.

Returns the function that will be used to generate random bytes.
生成将用于生成随机返回的函数字节。
*/
uECC_RNG_Function uECC_get_rng(void);

/* 03、uECC_curve_private_key_size() function.

Returns the size of a private key for the curve in bytes.
返回曲线的私钥大小（字节）
*/
int uECC_curve_private_key_size(uECC_Curve curve);

/* 04、uECC_curve_public_key_size() function.

Returns the size of a public key for the curve in bytes.
返回曲线的公钥大小（字节）
*/
int uECC_curve_public_key_size(uECC_Curve curve);

/* 05、uECC_make_key() function.
Create a public/private key pair.
创建公钥/私钥的密钥对

Outputs:
    public_key  - Will be filled in with the public key. Must be at least 2 * the curve size
                  (in bytes) long. For example, if the curve is secp256r1, public_key must be 64
                  bytes long.
                  将用公钥填充。长度必须至少为曲线大小（字节）的2倍。例如，如果曲线为secp256r1，则公钥必须为64字节长。
    private_key - Will be filled in with the private key. Must be as long as the curve order; this
                  is typically the same as the curve size, except for secp160r1. For example, if the
                  curve is secp256r1, private_key must be 32 bytes long.
                  将用私钥填充。必须与曲线的顺序一样长；除secp160r1外，这通常与曲线大小相同。例如，如果曲线是secp256r1，则私钥的长度必须为32字节。

                  For secp160r1, private_key must be 21 bytes long! Note that the first byte will
                  almost always be 0 (there is about a 1 in 2^80 chance of it being non-zero).
                  对于secp160r1，私钥的长度必须为21字节！请注意，第一个字节几乎总是0（约有1/2^80的可能性为非零）。

Returns 1 if the key pair was generated successfully, 0 if an error occurred.
*/
int uECC_make_key(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve);

/* 06、uECC_shared_secret() function.
Compute a shared secret given your secret key and someone else's public key. If the public key
is not from a trusted source and has not been previously verified, you should verify it first
using uECC_valid_public_key().
根据您的密钥和其他人的公钥计算共享密钥。如果公钥不是来自受信任的来源，并且之前未经验证，则应首先使用uECC_valid_public_key() 进行验证。
Note: It is recommended that you hash the result of uECC_shared_secret() before using it for
symmetric encryption or HMAC.
注意：建议在将uECC_shared_secret() 的结果用于对称加密或HMAC之前对其进行散列。

Inputs:
    public_key  - The public key of the remote party. 对方的公钥
    private_key - Your private key. 你的私钥

Outputs:
    secret - Will be filled in with the shared secret value. Must be the same size as the
             curve size; for example, if the curve is secp256r1, secret must be 32 bytes long.
             将用共享秘密值填充。必须与曲线大小相同；例如，如果曲线为secp256r1，则secret的长度必须为32字节。

Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
如果成功生成共享密钥，则返回1；如果发生错误，则返回0。
*/
int uECC_shared_secret(const uint8_t *public_key,
                       const uint8_t *private_key,
                       uint8_t *secret,
                       uECC_Curve curve);

#if uECC_SUPPORT_COMPRESSED_POINT
/* 07、uECC_compress() function.
Compress a public key.
压缩公钥

Inputs:
    public_key - The public key to compress. 要压缩的公钥

Outputs:
    compressed - Will be filled in with the compressed public key. Must be at least
                 (curve size + 1) bytes long; for example, if the curve is secp256r1,
                 compressed must be 33 bytes long.
                 压缩-将用压缩公钥填充。长度必须至少为（曲线大小+1）字节；例如，如果曲线是secp256r1，则压缩长度必须为33字节。
*/
void uECC_compress(const uint8_t *public_key, uint8_t *compressed, uECC_Curve curve);

/* 08、uECC_decompress() function.
Decompress a compressed public key.
解压公钥

Inputs:
    compressed - The compressed public key. 压缩的公钥。

Outputs:
    public_key - Will be filled in with the decompressed public key. 将用解压缩的公钥填充。
*/
void uECC_decompress(const uint8_t *compressed, uint8_t *public_key, uECC_Curve curve);
#endif /* uECC_SUPPORT_COMPRESSED_POINT */

/* 09、uECC_valid_public_key() function.
Check to see if a public key is valid.
检查公钥是否有效。

Note that you are not required to check for a valid public key before using any other uECC
functions. However, you may wish to avoid spending CPU time computing a shared secret or
verifying a signature using an invalid public key.
请注意，在使用任何其他uECC功能之前，不需要检查有效的公钥。但是，您可能希望避免花费CPU时间计算共享密钥或使用无效公钥验证签名。

Inputs:
    public_key - The public key to check. 要检查的公钥。

Returns 1 if the public key is valid, 0 if it is invalid.
如果公钥有效，则返回1；如果公钥无效，则返回0。
*/
int uECC_valid_public_key(const uint8_t *public_key, uECC_Curve curve);

/* 10、uECC_compute_public_key() function.
Compute the corresponding public key for a private key.
为私钥计算相应的公钥。

Inputs:
    private_key - The private key to compute the public key for 为其计算公钥的私钥

Outputs:
    public_key - Will be filled in with the corresponding public key 将填充相应的公钥

Returns 1 if the key was computed successfully, 0 if an error occurred.
如果密钥计算成功，则返回1；如果发生错误，则返回0。
*/
int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);

/* 11、uECC_sign() function.
Generate an ECDSA signature for a given hash value.
为给定哈希值生成ECDSA签名。

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key.
用法：计算要签名的数据的散列（建议使用SHA-2），并将其与私钥一起传递到此函数。

Inputs:
    private_key  - Your private key. 你的私钥。
    message_hash - The hash of the message to sign. 要签名的消息的散列。
    hash_size    - The size of message_hash in bytes.  message_hash的大小（字节）

Outputs:
    signature - Will be filled in with the signature value. Must be at least 2 * curve size long.
                For example, if the curve is secp256r1, signature must be 64 bytes long.
                将用签名值填充。曲线长度必须至少为2*。例如，如果曲线为secp256r1，则签名长度必须为64字节。

Returns 1 if the signature generated successfully, 0 if an error occurred.
如果成功生成签名，则返回1；如果发生错误，则返回0。
*/
int uECC_sign(const uint8_t *private_key,
              const uint8_t *message_hash,
              unsigned hash_size,
              uint8_t *signature,
              uECC_Curve curve);

/* uECC_HashContext structure.
This is used to pass in an arbitrary hash function to uECC_sign_deterministic().
The structure will be used for multiple hash computations; each time a new hash
is computed, init_hash() will be called, followed by one or more calls to
update_hash(), and finally a call to finish_hash() to produce the resulting hash.
这用于将任意哈希函数传递给uECC_sign_deterministic()。该结构将用于多个散列计算；每次计算新的哈希时，都会调用init_hash()，
然后调用一个或多个update_hash()的调用，最后调用finish_hash()生成结果哈希。

The intention is that you will create a structure that includes uECC_HashContext
followed by any hash-specific data. For example:
其目的是创建一个包含uECC_HashContext的结构，后跟任何特定于散列的数据。例如：

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

void init_SHA256(uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    SHA256_Init(&context->ctx);
}

void update_SHA256(uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    SHA256_Update(&context->ctx, message, message_size);
}

void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    SHA256_Final(hash_result, &context->ctx);
}

... when signing ...
{
    uint8_t tmp[32 + 32 + 64];
    SHA256_HashContext ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
    uECC_sign_deterministic(key, message_hash, &ctx.uECC, signature);
}
*/
typedef struct uECC_HashContext {
    void (*init_hash)(const struct uECC_HashContext *context);
    void (*update_hash)(const struct uECC_HashContext *context,
                        const uint8_t *message,
                        unsigned message_size);
    void (*finish_hash)(const struct uECC_HashContext *context, uint8_t *hash_result);
    unsigned block_size; /* Hash function block size in bytes, eg 64 for SHA-256. */
    unsigned result_size; /* Hash function result size in bytes, eg 32 for SHA-256. */
    uint8_t *tmp; /* Must point to a buffer of at least (2 * result_size + block_size) bytes. */
} uECC_HashContext;

/* 12、uECC_sign_deterministic() function.
Generate an ECDSA signature for a given hash value, using a deterministic algorithm
(see RFC 6979). You do not need to set the RNG using uECC_set_rng() before calling
this function; however, if the RNG is defined it will improve resistance to side-channel
attacks.
使用确定性算法为给定哈希值生成ECDSA签名（请参阅RFC 6979）。在调用此函数之前，不需要使用uECC_set_rng()设置RNG；然而，如果定义了RNG，它将提高对侧通道攻击的抵抗力。

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it to
this function along with your private key and a hash context. Note that the message_hash
does not need to be computed with the same hash function used by hash_context.
用法：计算要签名的数据的散列（建议使用SHA-2），并将其与私钥和散列上下文一起传递给此函数。请注意，不需要使用hash_context使用的相同哈希函数来计算消息_哈希。

Inputs:
    private_key  - Your private key. 你的私钥。
    message_hash - The hash of the message to sign. 要签名的消息的散列。
    hash_size    - The size of message_hash in bytes. message_hash消息的大小（字节）
    hash_context - A hash context to use. 要使用的哈希上下文。

Outputs:
    signature - Will be filled in with the signature value. 将用签名值填充。

Returns 1 if the signature generated successfully, 0 if an error occurred.
如果成功生成签名，则返回1；如果发生错误，则返回0。
*/
int uECC_sign_deterministic(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            const uECC_HashContext *hash_context,
                            uint8_t *signature,
                            uECC_Curve curve);

/* 13、uECC_verify() function.
Verify an ECDSA signature.
验证ECDSA签名。

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).
用法：使用与签名者相同的散列计算签名数据的散列，并将其与签名者的公钥和签名值（r和s）一起传递给此函数。

Inputs:
    public_key   - The signer's public key. 签名者的公钥。
    message_hash - The hash of the signed data. 签名数据的散列。
    hash_size    - The size of message_hash in bytes. message_hash的大小（字节）
    signature    - The signature value. 签名值。

Returns 1 if the signature is valid, 0 if it is invalid.
如果签名有效，则返回1；如果签名无效，则返回0。
*/
int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature,
                uECC_Curve curve);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _UECC_H_ */
