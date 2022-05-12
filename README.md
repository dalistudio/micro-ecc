micro-ecc
==========

A small and fast ECDH and ECDSA implementation for 8-bit, 32-bit, and 64-bit processors.
一个基于8位、32位和64位处理器，且小而快的ECDH和ECDSA实现。

The static version of micro-ecc (ie, where the curve was selected at compile-time) can be found in the "static" branch.
micro-ecc的静态版本（例如编译时确定曲线），可以签出"static"分支。


修改需求
--------
01、仅支持X86平台
02、仅支持64bit处理器
03、仅支持secp256k1曲线和95bit密钥实现的cd-key
04、独立大数计算库（仅实现ECC需要）

Features
特点
--------

 * Resistant to known side-channel attacks.
 * 抵抗已知的 side-channel攻击。
 * Written in C, with optional GCC inline assembly for AVR, ARM and Thumb platforms.
 * 用C语言编写，带有可选的GCC内联汇编，用于AVR、ARM和Thumb平台。
 * Supports 8, 32, and 64-bit architectures.
 * 支持 8、32和64位的架构。
 * Small code size.
 * 代码量小。
 * No dynamic memory allocation.
 * 没有动态内存分配。
 * Support for 5 standard curves: secp160r1, secp192r1, secp224r1, secp256r1, and secp256k1.
 * 支持5种标准曲线：secp160r1、secp192r1、secp224r1、secp256r1和secp256k1。
 * BSD 2-clause license.
 * BSD 2条款许可证

Usage Notes
使用说明
-----------
### Point Representation ###
### 点表示法 ###
Compressed points are represented in the standard format as defined in http://www.secg.org/sec1-v2.pdf; uncompressed points are represented in standard format, but without the `0x04` prefix. All functions except `uECC_decompress()` only accept uncompressed points; use `uECC_compress()` and `uECC_decompress()` to convert between compressed and uncompressed point representations.
压缩点以http://www.secg.org/sec1-v2.pdf中定义的标准格式表示；未压缩点以标准格式表示，但没有"0x04"前缀。除"uECC_decompress()"之外的所有函数只接受未压缩点；使用"uECC_compress()"和"uECC_decompress()"在压缩点和未压缩点表示之间进行转换。

Private keys are represented in the standard format.
私钥以标准格式表示。

### Using the Code ###
### 使用代码 ###
I recommend just copying (or symlink) the uECC files into your project. Then just `#include "uECC.h"` to use the micro-ecc functions.
我建议将uECC文件复制（或链接）到您的项目中，然后只需要引用 #include "uECC.h 即可使用micro-ecc的功能。

For use with Arduino, you can use the Library Manager to download micro-ecc (**Sketch**=>**Include Library**=>**Manage Libraries**). You can then use uECC just like any other Arduino library (uECC should show up in the **Sketch**=>**Import Library** submenu).
要与 Arduino一起使用，您可以使用库管理器下载 micro-ecc（**Sketch**=>**Include Library**=>**Manage Libraries**）。然后，您可以像使用任何其他Arduino库一样使用uECC（uECC应该显示在**Sketch**=>**Import Library**子菜单中）。

See uECC.h for documentation for each function.
每个函数的文档，请查看 uECC.h


### Compilation Notes ###
### 编译说明 ###

 * Should compile with any C/C++ compiler that supports stdint.h (this includes Visual Studio 2013).
 * 应该使用任何支持 stdint.h 的C/C++编译器（包括Visual Studio 2013）.
 * If you want to change the defaults for any of the uECC compile-time options (such as `uECC_OPTIMIZATION_LEVEL`), you must change them in your Makefile or similar so that uECC.c is compiled with the desired values (ie, compile uECC.c with `-DuECC_OPTIMIZATION_LEVEL=3` or whatever).
 * 如果要更改任何uECC编译时选项（例如"uECC_OPTIMIZATION_LEVEL"）的默认值，则必须在Makefile或类似文件中更改它们，以便uECC.c是用所需的值编译的（即用"-DuECC_OPTIMIZATION_LEVEL=3"编译uECC.c或其它任何值）。
 * When compiling for a Thumb-1 platform, you must use the `-fomit-frame-pointer` GCC option (this is enabled by default when compiling with `-O1` or higher).
 * 在为 Thumb-a 平台编译时，必须使用"-fomit-frame-pointer" GCC选项（在使用"-O1"或更高编译时默认启用）。
 * When compiling for an ARM/Thumb-2 platform with `uECC_OPTIMIZATION_LEVEL` >= 3, you must use the `-fomit-frame-pointer` GCC option (this is enabled by default when compiling with `-O1` or higher).
 * 为"uECC_OPTIMIZATION_LEVEL" >=3 的 ARM/Thumb-2 平台编译时，必须使用"-fomit-frame-pointer" GCC选项（在使用"-O1"或更高编译时默认使用）。
 * When compiling for AVR, you must have optimizations enabled (compile with `-O1` or higher).
 * 为AVR编译时，必须启用优化（使用"-O1"或更高编译）
 * When building for Windows, you will need to link in the `advapi32.lib` system library.
 * 在构建Windows时，需要链接"advapi32.lib" 系统库。
