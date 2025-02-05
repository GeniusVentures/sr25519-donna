#ifndef PROJECT_SHA3_H_
#define PROJECT_SHA3_H_

#include <stddef.h>
#include <stdint.h>

typedef uint8_t crypto_uint8;
typedef int8_t crypto_int8;

typedef uint16_t crypto_uint16;
typedef int16_t crypto_int16;

typedef uint32_t crypto_uint32;
typedef int32_t crypto_int32;

typedef uint64_t crypto_uint64;
typedef int64_t crypto_int64;

typedef struct sha_context_t {
  unsigned char opaque[224]; // size of context in bytes
} sha_context;

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(uint64_t))
typedef struct sha3_context_ {
  uint64_t saved;             /* the portion of the input message that we
                                 * didn't consume yet */
  union {                     /* Keccak's state */
    uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
    uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
  };
  unsigned byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
  unsigned wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
  unsigned capacityWords;     /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
} sha3_context;

void sha3_Init256(void *context);

void sha3_Init384(void *context);

void sha3_Init512(void *context);

void sha3_Update(void *context, void const *bufIn, size_t len);

void sha3_Finalize(void *context, unsigned char *out);

#endif //  PROJECT_SHA3_H_
