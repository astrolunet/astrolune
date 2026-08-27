/*
 * astrolune/base.h - fundamental types, status codes and portability layer.
 *
 * This header is the root of the public C ABI. Every other public header
 * includes it, and it is compiled by both the C23 core and the C++23 tooling,
 * which constrains what may appear here:
 *
 *   - no `_Atomic`, `restrict` or C-only keywords in declarations,
 *   - no variable-length arrays,
 *   - no anonymous unions inside structs with C++-invalid layout,
 *   - no `constexpr`, `nullptr` or `enum : type` (MSVC reports C23 but does not
 *     implement these; verified against MSVC 19.51),
 *   - every enum has an explicit sentinel so its width is stable.
 *
 * The rules are spelled out in docs/02-architecture/c-cpp-boundary.md.
 */

#ifndef ASTROLUNE_BASE_H
#define ASTROLUNE_BASE_H

#include <stddef.h>
#include <stdint.h>

/* --------------------------------------------------------------------------
 * Linkage
 * -------------------------------------------------------------------------- */

#ifdef __cplusplus
#  define AL_EXTERN_C_BEGIN extern "C" {
#  define AL_EXTERN_C_END   }
#else
#  define AL_EXTERN_C_BEGIN
#  define AL_EXTERN_C_END
#endif

AL_EXTERN_C_BEGIN

/* --------------------------------------------------------------------------
 * Compiler and platform detection
 * -------------------------------------------------------------------------- */

#if defined(__clang__)
#  define AL_COMPILER_CLANG 1
#elif defined(__GNUC__)
#  define AL_COMPILER_GCC 1
#elif defined(_MSC_VER)
#  define AL_COMPILER_MSVC 1
#else
#  error "Unsupported compiler. Astrolune requires GCC, Clang or MSVC."
#endif

#if defined(_WIN32)
#  define AL_OS_WINDOWS 1
#elif defined(__linux__)
#  define AL_OS_LINUX 1
#elif defined(__APPLE__)
#  define AL_OS_MACOS 1
#endif

#if defined(__x86_64__) || defined(_M_X64)
#  define AL_ARCH_X86_64 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#  define AL_ARCH_ARM64 1
#endif

/* --------------------------------------------------------------------------
 * Attributes
 *
 * Spelled through macros rather than used directly: the C23 attribute syntax is
 * only partially available across the three compilers we support, and the core
 * must build identically on all of them.
 * -------------------------------------------------------------------------- */

#if defined(__cplusplus)
#  define AL_NODISCARD     [[nodiscard]]
#  define AL_MAYBE_UNUSED  [[maybe_unused]]
#  define AL_NORETURN      [[noreturn]]
#elif defined(AL_COMPILER_MSVC)
/* MSVC accepts C23 attribute syntax in C mode for these three. */
#  define AL_NODISCARD     [[nodiscard]]
#  define AL_MAYBE_UNUSED  [[maybe_unused]]
#  define AL_NORETURN      [[noreturn]]
#else
#  define AL_NODISCARD     __attribute__((warn_unused_result))
#  define AL_MAYBE_UNUSED  __attribute__((unused))
#  define AL_NORETURN      __attribute__((noreturn))
#endif

/* Marks declarations that belong to the stable public C ABI. It is empty for
 * static builds; keeping the marker separate lets shared-library visibility
 * and the ABI manifest checker evolve without rewriting every prototype. */
#define AL_PUBLIC

#if defined(AL_COMPILER_MSVC)
#  define AL_FORCEINLINE   __forceinline
#  define AL_NOINLINE      __declspec(noinline)
#  define AL_ALIGNAS(n)    __declspec(align(n))
#  define AL_LIKELY(x)     (x)
#  define AL_UNLIKELY(x)   (x)
#  define AL_UNREACHABLE() __assume(0)
#else
#  define AL_FORCEINLINE   __attribute__((always_inline)) inline
#  define AL_NOINLINE      __attribute__((noinline))
#  define AL_ALIGNAS(n)    __attribute__((aligned(n)))
#  define AL_LIKELY(x)     __builtin_expect(!!(x), 1)
#  define AL_UNLIKELY(x)   __builtin_expect(!!(x), 0)
#  define AL_UNREACHABLE() __builtin_unreachable()
#endif

/* `restrict` is a C keyword with no standard C++ spelling. Public prototypes
 * use AL_RESTRICT so the same declaration is valid in both languages. */
#if defined(__cplusplus)
#  if defined(AL_COMPILER_MSVC)
#    define AL_RESTRICT __restrict
#  else
#    define AL_RESTRICT __restrict__
#  endif
#else
#  define AL_RESTRICT restrict
#endif

/* Compile-time assertion usable from either language and from any C mode. */
#if defined(__cplusplus)
#  define AL_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
/* C11 and later. Every compiler Astrolune supports provides this, so there is
 * no typedef-based fallback to get subtly wrong. */
#  define AL_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* Explicit cast usable from either language.
 *
 * A C cast is legal C++ but the tooling builds with -Wold-style-cast, so a
 * macro in a shared header that expands to one would make every C++ user of
 * that macro a warning - and an error under the ci and asan presets. Casts in
 * this header set therefore route through AL_CAST. In C the expansion is
 * character-for-character what a hand-written cast would be, so the core is
 * unaffected. `(void)` casts are exempt from the warning and stay as they are. */
#if defined(__cplusplus)
#  define AL_CAST(T, v) static_cast<T>(v)
#else
#  define AL_CAST(T, v) ((T)(v))
#endif

/* Number of elements in a true array. Deliberately not applied to pointers;
 * misuse is caught by the surrounding -Wsizeof-pointer-div warning. */
#define AL_COUNTOF(a) (sizeof(a) / sizeof((a)[0]))

#define AL_UNUSED(x) ((void)(x))

/* --------------------------------------------------------------------------
 * Scalar types
 *
 * The core uses these spellings rather than the raw stdint names so that the
 * width of a consensus-visible field is obvious at the point of use. Anything
 * serialised into a block or hashed must use a fixed-width type.
 * -------------------------------------------------------------------------- */

typedef uint8_t  al_u8;
typedef uint16_t al_u16;
typedef uint32_t al_u32;
typedef uint64_t al_u64;
typedef int8_t   al_i8;
typedef int16_t  al_i16;
typedef int32_t  al_i32;
typedef int64_t  al_i64;

typedef size_t   al_size;

/* Boolean with a fixed, serialisable width. C23's `bool` is one byte in
 * practice but its size is not pinned by the standard, and the ABI is shared
 * with C++ where `bool` is a distinct type. */
typedef al_u8 al_bool;
#define AL_TRUE  AL_CAST(al_bool, 1)
#define AL_FALSE AL_CAST(al_bool, 0)

/*
 * Consensus-critical arithmetic never uses floating point.
 *
 * Float results depend on the FPU mode, the instruction selection and the
 * compiler's contraction choices, which differ between machines. For a
 * blockchain that is not a rounding difference, it is a chain split. Every
 * quantity the protocol scores or compares is an integer or the fixed-point
 * type in astrolune/fixed.h.
 */

/* Token amounts. u64 with 9 decimal places, giving a maximum representable
 * supply of ~1.8e10 whole tokens - the same trade-off Solana and TON make, and
 * it avoids a portable 128-bit type (MSVC has no __int128). */
typedef al_u64 al_amount;
#define AL_DECIMALS       9
#define AL_UNITS_PER_COIN UINT64_C(1000000000)

/* Block heights and gas are monotone counters; nonces are per-account. */
typedef al_u64 al_height;
typedef al_u64 al_gas;
typedef al_u64 al_nonce;

/* Consensus resources are accounted independently. Conflating persistent
 * storage and transient CPU work into one counter would bake an arbitrary
 * exchange rate into every transaction and make repricing either resource a
 * protocol-breaking change. */
typedef struct al_resources {
    al_u64 compute;
    al_u64 memory;
    al_u64 storage;
    al_u64 bandwidth;
} al_resources;

typedef struct al_fee_params {
    al_resources block_limit;
    al_resources target;
    al_resources initial_base_price;
    al_amount     storage_deposit_per_byte;
} al_fee_params;

/* --------------------------------------------------------------------------
 * Byte arrays
 *
 * Hashes and addresses are wrapped in structs rather than used as raw arrays so
 * that they are values: assignable, returnable, and impossible to silently
 * decay to a pointer or to be confused with each other.
 * -------------------------------------------------------------------------- */

#define AL_HASH_SIZE      32
#define AL_ADDRESS_SIZE   32
#define AL_PUBKEY_SIZE    32
#define AL_SECKEY_SIZE    64
#define AL_SIGNATURE_SIZE 64

typedef struct al_hash256 { al_u8 bytes[AL_HASH_SIZE];      } al_hash256;
typedef struct al_address { al_u8 bytes[AL_ADDRESS_SIZE];    } al_address;
typedef struct al_pubkey  { al_u8 bytes[AL_PUBKEY_SIZE];     } al_pubkey;
typedef struct al_seckey  { al_u8 bytes[AL_SECKEY_SIZE];     } al_seckey;
typedef struct al_sig     { al_u8 bytes[AL_SIGNATURE_SIZE];  } al_sig;

AL_STATIC_ASSERT(sizeof(al_hash256) == 32, "al_hash256 must be exactly 32 bytes");
AL_STATIC_ASSERT(sizeof(al_address) == 32, "al_address must be exactly 32 bytes");

/* --------------------------------------------------------------------------
 * Status codes
 *
 * The core reports failure by return value, never by exception, errno or a
 * global. Functions that produce a value take an out-parameter and return
 * al_status. Anything that can fail is AL_NODISCARD.
 * -------------------------------------------------------------------------- */

typedef enum al_status {
    AL_OK = 0,

    /* Caller errors */
    AL_ERR_INVALID_ARG = 1,
    AL_ERR_OUT_OF_RANGE,
    AL_ERR_BUFFER_TOO_SMALL,
    AL_ERR_UNSUPPORTED,
    AL_ERR_NOT_FOUND,
    AL_ERR_ALREADY_EXISTS,

    /* Resource errors */
    AL_ERR_OUT_OF_MEMORY = 32,
    AL_ERR_IO,

    /* Encoding errors */
    AL_ERR_MALFORMED = 64,       /* structurally invalid input            */
    AL_ERR_NOT_CANONICAL,        /* valid shape, non-canonical encoding   */
    AL_ERR_TRUNCATED,
    AL_ERR_TRAILING_BYTES,

    /* Cryptographic errors */
    AL_ERR_BAD_SIGNATURE = 96,
    AL_ERR_BAD_PROOF,

    /* Execution errors */
    AL_ERR_OUT_OF_GAS = 128,
    AL_ERR_VM_TRAP,
    AL_ERR_STACK_OVERFLOW,
    AL_ERR_INVALID_OPCODE,
    AL_ERR_DIVIDE_BY_ZERO,
    AL_ERR_ARITH_OVERFLOW,
    AL_ERR_MEMORY_FAULT,
    AL_ERR_CALL_DEPTH,
    AL_ERR_REVERTED,             /* contract asked to revert; not a bug   */
    AL_ERR_RESOURCE_LIMIT,
    AL_ERR_REENTRANCY,

    /* State and consensus errors */
    AL_ERR_INSUFFICIENT_FUNDS = 160,
    AL_ERR_BAD_NONCE,
    AL_ERR_STATE_CORRUPT,
    AL_ERR_CONSENSUS_VIOLATION,
    AL_ERR_EXPIRED,

    AL_STATUS_SENTINEL = 0x7fffffff  /* pins the enum's width */
} al_status;

/* Stable, allocation-free description of a status. Never returns NULL. */
AL_PUBLIC const char *al_status_str(al_status status);

/* True for AL_OK only; written as a function so it is usable from C++ too. */
AL_PUBLIC AL_NODISCARD al_bool al_ok(al_status status);

/* Resource arithmetic is checked rather than saturating: accepting a block
 * after silently clipping its usage would let different validation paths
 * disagree about whether the block exceeded a limit. */
AL_PUBLIC al_resources al_resources_zero(void);
AL_PUBLIC AL_NODISCARD al_status al_resources_add(al_resources a,
                                                  al_resources b,
                                                  al_resources *out);
AL_PUBLIC AL_NODISCARD al_bool al_resources_within(al_resources used,
                                                   al_resources limit);
AL_PUBLIC AL_NODISCARD al_status al_resources_fee(al_resources used,
                                                  al_resources prices,
                                                  al_amount *out);
AL_PUBLIC AL_NODISCARD al_status al_fee_next_base_prices(
    al_resources parent_prices, al_resources parent_used,
    al_resources target, al_resources *out);

/*
 * Early-return helper for the core's internal code.
 *
 * Deliberately not a `goto cleanup` macro: the core allocates from arenas that
 * are reset by the caller, so a plain early return leaks nothing and keeps the
 * control flow readable.
 */
#define AL_TRY(expr)                          \
    do {                                      \
        const al_status al_try_ = (expr);     \
        if (al_try_ != AL_OK) return al_try_; \
    } while (0)

/* --------------------------------------------------------------------------
 * Version
 * -------------------------------------------------------------------------- */

#define AL_VERSION_MAJOR 0
#define AL_VERSION_MINOR 1
#define AL_VERSION_PATCH 0

/* "0.1.0" - the same string the CLI prints for --version. */
AL_PUBLIC const char *al_version_string(void);

AL_EXTERN_C_END

#endif /* ASTROLUNE_BASE_H */
