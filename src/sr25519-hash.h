#ifndef __SR25519_HASH_H__
#define __SR25519_HASH_H__

#if defined(SR25519_CUSTOMHASH)

#include "sr25519-hash-custom.h"

#elif defined(SR25519_HASH_SHA3_BRAINHUB)

#include "sha3.h"

typedef sha3_context sr25519_hash_context;

static void
sr25519_hash_init(sr25519_hash_context* ctx) {
  sha3_Init512(ctx);
}

static void
sr25519_hash_update(sr25519_hash_context* ctx, const uint8_t* in, size_t inlen) {
  sha3_Update(ctx, in, inlen);
}

static void
sr25519_hash_final(sr25519_hash_context* ctx, uint8_t* hash) {
  sha3_Finalize(ctx, hash);
}

static void
sr25519_hash(uint8_t* hash, const uint8_t* in, size_t inlen) {
  sha_context ctx = {0};
  sha3_Init512(&ctx);
  sha3_Update(&ctx, in, inlen);
  sha3_Finalize(&ctx, hash);
}

#else

#include "sha2.h"

typedef SHA512_CTX sr25519_hash_context;

static void
sr25519_hash_init(sr25519_hash_context *ctx) {
    sha512_Init(ctx);
}

static void
sr25519_hash_update(sr25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
    sha512_Update(ctx, in, inlen);
}

static void
sr25519_hash_final(sr25519_hash_context *ctx, uint8_t *hash) {
    sha512_Final(ctx, hash);
}

static void
sr25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
    sha512_Raw(in, inlen, hash);
}

#endif

#endif
