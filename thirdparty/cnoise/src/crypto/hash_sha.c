/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <assert.h>
#include <openssl/sha.h>

#include <internal.h>

typedef struct {
    struct NoiseHashState_s parent;
    union {
        SHA256_CTX sha256_ctx;
        SHA512_CTX sha512_ctx;
    };

} NoiseHashState_ex;

static void noise_sha_reset(NoiseHashState *state) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    assert(st->parent.hash_id == NOISE_HASH_SHA256
           || st->parent.hash_id == NOISE_HASH_SHA512);

    if (st->parent.hash_id == NOISE_HASH_SHA256)
        SHA256_Init(&st->sha256_ctx);
    else if (st->parent.hash_id == NOISE_HASH_SHA512)
        SHA512_Init(&st->sha512_ctx);
}

static void noise_sha_update(NoiseHashState *state, const uint8_t *data, size_t len) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    assert(st->parent.hash_id == NOISE_HASH_SHA256
           || st->parent.hash_id == NOISE_HASH_SHA512);

    if (st->parent.hash_id == NOISE_HASH_SHA256)
        SHA256_Update(&st->sha256_ctx, data, len);
    else if (st->parent.hash_id == NOISE_HASH_SHA512)
        SHA512_Update(&st->sha512_ctx, data, len);
}

static void noise_sha_finalize(NoiseHashState *state, uint8_t *hash) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    assert(st->parent.hash_id == NOISE_HASH_SHA256
           || st->parent.hash_id == NOISE_HASH_SHA512);

    if (st->parent.hash_id == NOISE_HASH_SHA256)
        SHA256_Final(hash, &st->sha256_ctx);
    else if (st->parent.hash_id == NOISE_HASH_SHA512)
        SHA512_Final(hash, &st->sha512_ctx);
}

NoiseHashState *noise_sha_new(uint16_t type) {
    NoiseHashState_ex *state = noise_new(NoiseHashState_ex);
    if (!state)
        return NULL;
    state->parent.hash_id = type;
    if (type == NOISE_HASH_SHA256) {
        state->parent.hash_len  = 32;
        state->parent.block_len = 64;
    } else if (type == NOISE_HASH_SHA512) {
        state->parent.hash_len  = 64;
        state->parent.block_len = 128;
    } else
        return NULL;

    state->parent.reset    = noise_sha_reset;
    state->parent.update   = noise_sha_update;
    state->parent.finalize = noise_sha_finalize;
    return &(state->parent);
}
