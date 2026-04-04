#include <assert.h>
#include <blake2.h>

#include <internal.h>

typedef struct {
    struct NoiseHashState_s parent;
    union {
        blake2s_state b2s_ctx;
        blake2b_state b2b_ctx;
    };
} NoiseHashState_ex;

static void noise_blake_reset(NoiseHashState *state) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    assert(st->parent.hash_id == NOISE_HASH_BLAKE2s
           || st->parent.hash_id == NOISE_HASH_BLAKE2b);

    if (st->parent.hash_id == NOISE_HASH_BLAKE2s)
        blake2s_init(&st->b2s_ctx, st->parent.hash_len);
    else if (st->parent.hash_id == NOISE_HASH_BLAKE2b)
        blake2b_init(&st->b2b_ctx, st->parent.hash_len);
}

static void noise_blake_update(NoiseHashState *state, const uint8_t *data, size_t len) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    assert(st->parent.hash_id == NOISE_HASH_BLAKE2s
           || st->parent.hash_id == NOISE_HASH_BLAKE2b);

    if (st->parent.hash_id == NOISE_HASH_BLAKE2s)
        blake2s_update(&st->b2s_ctx, data, len);
    else if (st->parent.hash_id == NOISE_HASH_BLAKE2b)
        blake2b_update(&st->b2b_ctx, data, len);
}

static void noise_blake_finalize(NoiseHashState *state, uint8_t *hash) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    assert(st->parent.hash_id == NOISE_HASH_BLAKE2s
           || st->parent.hash_id == NOISE_HASH_BLAKE2b);

    if (st->parent.hash_id == NOISE_HASH_BLAKE2s)
        blake2s_final(&st->b2s_ctx, hash, st->parent.hash_len);
    else if (st->parent.hash_id == NOISE_HASH_BLAKE2b)
        blake2b_final(&st->b2b_ctx, hash, st->parent.hash_len);
}

NoiseHashState *noise_blake_new(uint16_t type) {
    NoiseHashState_ex *state = noise_new(NoiseHashState_ex);
    if (!state)
        return NULL;
    state->parent.hash_id = type;
    if (type == NOISE_HASH_BLAKE2s) {
        state->parent.hash_len  = 32;
        state->parent.block_len = 64;
    } else if (type == NOISE_HASH_BLAKE2b) {
        state->parent.hash_len  = 64;
        state->parent.block_len = 128;
    } else
        return NULL;

    state->parent.reset    = noise_blake_reset;
    state->parent.update   = noise_blake_update;
    state->parent.finalize = noise_blake_finalize;
    return &(state->parent);
}
