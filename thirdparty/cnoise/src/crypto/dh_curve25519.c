#include <string.h>

#include <internal.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>

#define LOCAL_KEY_SIZE X25519_KEY_LENGTH

typedef struct {
    struct NoiseDHState_s parent;
    uint8_t               private_key[LOCAL_KEY_SIZE];
    uint8_t               public_key[LOCAL_KEY_SIZE];
} NoiseDHState_ex;

static int noise_curve25519_generate_keypair(NoiseDHState       *state,
                                             const NoiseDHState *other) {
    NoiseDHState_ex *st = (NoiseDHState_ex *) state;
    X25519_keypair(st->public_key, st->private_key);
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_set_keypair(NoiseDHState *state, const uint8_t *private_key,
                                        const uint8_t *public_key) {
    NoiseDHState_ex *st = (NoiseDHState_ex *) state;

    int     equal;
    uint8_t public_key_tmp[sizeof(st->public_key)];
    size_t  public_key_tmp_len = sizeof(public_key_tmp);

    // Derives public key from private key
    EVP_PKEY *private_key_ctx =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, LOCAL_KEY_SIZE);
    EVP_PKEY_get_raw_public_key(private_key_ctx, public_key_tmp, &public_key_tmp_len);
    EVP_PKEY_free(private_key_ctx);

    equal = noise_is_equal(public_key_tmp, public_key, st->parent.public_key_len);
    memcpy(st->private_key, private_key, st->parent.private_key_len);
    memcpy(st->public_key, public_key, st->parent.public_key_len);

    return NOISE_ERROR_INVALID_PUBLIC_KEY & (equal - 1);
}

static int noise_curve25519_set_keypair_private(NoiseDHState  *state,
                                                const uint8_t *private_key) {
    NoiseDHState_ex *st = (NoiseDHState_ex *) state;
    memcpy(st->private_key, private_key, st->parent.private_key_len);

    // Derives public key from private key
    size_t    public_key_len = sizeof(st->public_key);
    EVP_PKEY *private_key_ctx =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, LOCAL_KEY_SIZE);
    EVP_PKEY_get_raw_public_key(private_key_ctx, st->parent.public_key, &public_key_len);
    EVP_PKEY_free(private_key_ctx);

    if (public_key_len != LOCAL_KEY_SIZE)
        return NOISE_ERROR_INVALID_LENGTH;

    return NOISE_ERROR_NONE;
}

static int noise_curve25519_validate_public_key(const NoiseDHState *state,
                                                const uint8_t      *public_key) {
    /* Nothing to do here yet */
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_copy(NoiseDHState *state, const NoiseDHState *from,
                                 const NoiseDHState *other) {
    NoiseDHState_ex       *st      = (NoiseDHState_ex *) state;
    const NoiseDHState_ex *from_st = (const NoiseDHState_ex *) from;
    memcpy(st->private_key, from_st->private_key, st->parent.private_key_len);
    memcpy(st->public_key, from_st->public_key, st->parent.public_key_len);
    return NOISE_ERROR_NONE;
}

static int noise_curve25519_calculate(const NoiseDHState *private_key_state,
                                      const NoiseDHState *public_key_state,
                                      uint8_t            *shared_key) {
    X25519(shared_key, private_key_state->private_key, public_key_state->public_key);
    return NOISE_ERROR_NONE;
}
NoiseDHState *noise_curve25519_new(void) {
    NoiseDHState_ex *state = noise_new(NoiseDHState_ex);
    if (!state)
        return 0;

    state->parent.dh_id               = NOISE_DH_CURVE25519;
    state->parent.nulls_allowed       = 1;
    state->parent.private_key_len     = X25519_KEY_LENGTH;
    state->parent.public_key_len      = X25519_KEY_LENGTH;
    state->parent.shared_key_len      = X25519_KEY_LENGTH;
    state->parent.private_key         = state->private_key;
    state->parent.public_key          = state->public_key;
    state->parent.generate_keypair    = noise_curve25519_generate_keypair;
    state->parent.set_keypair         = noise_curve25519_set_keypair;
    state->parent.set_keypair_private = noise_curve25519_set_keypair_private;
    state->parent.validate_public_key = noise_curve25519_validate_public_key;
    state->parent.copy                = noise_curve25519_copy;
    state->parent.calculate           = noise_curve25519_calculate;
    return &(state->parent);
}

