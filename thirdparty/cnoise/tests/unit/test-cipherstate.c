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

#include "test-helpers.h"

#define MAX_KEY_LEN 32
#define MAX_AD_LEN 32
#define MAX_CIPHER_DATA 512
#define MAX_MAC_LEN 16

/* Check raw cipher output against test vectors */
static void check_cipher(int id, size_t key_len, size_t mac_len, const char *name,
                         const char *key, uint64_t nonce, const char *ad,
                         const char *plaintext, const char *ciphertext, const char *mac) {
    NoiseCipherState *state;
    NoiseBuffer       mbuf;
    uint8_t           k[MAX_KEY_LEN];
    uint8_t           a[MAX_AD_LEN];
    uint8_t           pt[MAX_CIPHER_DATA];
    uint8_t           ct[MAX_CIPHER_DATA];
    uint8_t           tag[MAX_MAC_LEN];
    uint8_t           buffer[MAX_CIPHER_DATA];
    size_t            pt_len;
    size_t            ad_len;

    /* Convert the test strings into binary data */
    compare(string_to_data(k, sizeof(k), key), key_len);
    ad_len = string_to_data(a, sizeof(a), ad);
    pt_len = string_to_data(pt, sizeof(pt), plaintext);
    compare(string_to_data(ct, sizeof(ct), ciphertext), pt_len);
    compare(string_to_data(tag, sizeof(tag), mac), mac_len);

    /* Create the cipher object and check its properties */
    compare(noise_cipherstate_new_by_id(&state, id), NOISE_ERROR_NONE);
    compare(noise_cipherstate_get_cipher_id(state), id);
    compare(noise_cipherstate_get_key_length(state), key_len);
    compare(noise_cipherstate_get_mac_length(state), mac_len);
    verify(!noise_cipherstate_has_key(state));
    verify(key_len <= noise_cipherstate_get_max_key_length());
    verify(mac_len <= noise_cipherstate_get_max_mac_length());

    /* Try to encrypt.  Because the key is not set yet, this will
       return the plaintext as-is */
    memcpy(buffer, pt, pt_len);
    noise_buffer_set_inout(mbuf, buffer, pt_len, sizeof(buffer));
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    compare(mbuf.size, pt_len);
    verify(!memcmp(mbuf.data, pt, pt_len));

    /* Try to encrypt again with no key.  This time specify a payload
       length that is too large */
    noise_buffer_set_input(mbuf, buffer, NOISE_MAX_PAYLOAD_LEN + 1);
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_LENGTH);

    /* One more plaintext encryption with a payload less than the MAC size */
    noise_buffer_set_inout(mbuf, buffer, mac_len / 2, sizeof(buffer));
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    compare(mbuf.size, mac_len / 2);

    /* Try to decrypt.  Will return the ciphertext and MAC as-is */
    memcpy(buffer, ct, pt_len);
    memcpy(buffer + pt_len, tag, mac_len);
    noise_buffer_set_input(mbuf, buffer, pt_len + mac_len);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    compare(mbuf.size, pt_len + mac_len);
    verify(!memcmp(mbuf.data, ct, pt_len));
    verify(!memcmp(mbuf.data + pt_len, tag, mac_len));

    /* Try to decrypt again with no key.  This time specify a payload
       length that is too large */
    noise_buffer_set_input(mbuf, buffer, NOISE_MAX_PAYLOAD_LEN + 1);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_LENGTH);

    /* Plaintext decryption can work with data less than the MAC size */
    noise_buffer_set_input(mbuf, buffer, mac_len / 2);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    compare(mbuf.size, mac_len / 2);

    /* Cannot set the nonce before we set the key */
    compare(noise_cipherstate_set_nonce(state, nonce), NOISE_ERROR_INVALID_STATE);

    /* Set the key and fast-forward the nonce */
    verify(!noise_cipherstate_has_key(state));
    compare(noise_cipherstate_init_key(state, k, key_len), NOISE_ERROR_NONE);
    compare(noise_cipherstate_set_nonce(state, nonce), NOISE_ERROR_NONE);
    verify(noise_cipherstate_has_key(state));

    /* Encrypt the data */
    memcpy(buffer, pt, pt_len);
    noise_buffer_set_inout(mbuf, buffer, pt_len, sizeof(buffer));
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    compare(mbuf.size, pt_len + mac_len);

    /* Check the ciphertext and MAC that was generated */
    verify(!memcmp(mbuf.data, ct, pt_len));
    verify(!memcmp(mbuf.data + pt_len, tag, mac_len));

    /* Try to decrypt.  The MAC check should fail because the internal
       nonce was incremented and no longer matches the parameter */
    noise_buffer_set_input(mbuf, buffer, pt_len + mac_len);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_MAC_FAILURE);

    /* Try to reset the nonce.  Cannot go backwards */
    compare(noise_cipherstate_set_nonce(state, nonce), NOISE_ERROR_INVALID_NONCE);

    /* Fast-forward the nonce to just before the rollover.  We will be able
       to encrypt one more block, and then the next request will be rejected */
    compare(noise_cipherstate_set_nonce(state, 0xFFFFFFFFFFFFFFFEULL), NOISE_ERROR_NONE);
    /* Rekey, which should not affect the nonce and should still allow us to
       encrypt one more block. */
    compare(noise_cipherstate_rekey(state), NOISE_ERROR_NONE);
    noise_buffer_set_inout(mbuf, buffer, pt_len, sizeof(buffer));
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    noise_buffer_set_inout(mbuf, buffer, pt_len, sizeof(buffer));
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_NONCE);

    /* Reset the key and then we can reset the nonce */
    compare(noise_cipherstate_init_key(state, k, key_len), NOISE_ERROR_NONE);
    compare(noise_cipherstate_set_nonce(state, nonce), NOISE_ERROR_NONE);

    /* Decrypt the test ciphertext and MAC */
    memcpy(buffer, ct, pt_len);
    memcpy(buffer + pt_len, tag, mac_len);
    noise_buffer_set_input(mbuf, buffer, pt_len + mac_len);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf), NOISE_ERROR_NONE);
    compare(mbuf.size, pt_len);

    /* Check that we got back to the original plaintext */
    verify(!memcmp(mbuf.data, pt, pt_len));

    /* Fast-forward the nonce to just before the rollover.  We will be able
       to decrypt one more block, and then the next request will be rejected */
    compare(noise_cipherstate_set_nonce(state, 0xFFFFFFFFFFFFFFFEULL), NOISE_ERROR_NONE);
    noise_buffer_set_input(mbuf, buffer, pt_len + mac_len);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_MAC_FAILURE); /* MAC will fail, but that's OK */
    noise_buffer_set_input(mbuf, buffer, pt_len + mac_len);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_MAC_FAILURE); /* MAC will fail again, nonce is not
                                        incremented on failed decryption */

    /* Reset the key to clear the "invalid nonce" state */
    compare(noise_cipherstate_init_key(state, k, key_len), NOISE_ERROR_NONE);

    /* Check for other parameter errors */
    compare(noise_cipherstate_init_key(0, k, key_len), NOISE_ERROR_INVALID_PARAM);
    compare(noise_cipherstate_init_key(state, 0, key_len), NOISE_ERROR_INVALID_PARAM);
    compare(noise_cipherstate_init_key(state, k, key_len - 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_cipherstate_init_key(state, k, key_len + 1),
            NOISE_ERROR_INVALID_LENGTH);
    compare(noise_cipherstate_set_nonce(0, nonce), NOISE_ERROR_INVALID_PARAM);
    noise_buffer_set_inout(mbuf, buffer, pt_len, sizeof(buffer));
    compare(noise_cipherstate_encrypt_with_ad(0, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_PARAM);
    if (ad_len) {
        compare(noise_cipherstate_encrypt_with_ad(state, 0, ad_len, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
    }
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, 0),
            NOISE_ERROR_INVALID_PARAM);
    mbuf.data = 0;
    compare(noise_cipherstate_encrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_PARAM);
    noise_buffer_set_inout(mbuf, buffer, pt_len + mac_len, sizeof(buffer));
    compare(noise_cipherstate_decrypt_with_ad(0, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_PARAM);
    if (ad_len) {
        compare(noise_cipherstate_decrypt_with_ad(state, 0, ad_len, &mbuf),
                NOISE_ERROR_INVALID_PARAM);
    }
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, 0),
            NOISE_ERROR_INVALID_PARAM);
    mbuf.data = 0;
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_PARAM);
    noise_buffer_set_input(mbuf, buffer, mac_len / 2);
    compare(noise_cipherstate_decrypt_with_ad(state, a, ad_len, &mbuf),
            NOISE_ERROR_INVALID_LENGTH);

    /* Re-create the object by name and check its properties again */
    compare(noise_cipherstate_free(state), NOISE_ERROR_NONE);
    compare(noise_cipherstate_new_by_name(&state, name), NOISE_ERROR_NONE);
    compare(noise_cipherstate_get_cipher_id(state), id);
    compare(noise_cipherstate_get_key_length(state), key_len);
    compare(noise_cipherstate_get_mac_length(state), mac_len);
    verify(!noise_cipherstate_has_key(state));

    /* Clean up */
    compare(noise_cipherstate_free(state), NOISE_ERROR_NONE);
}

/* Check against test vectors from the various specifications
   to validate that the algorithms work as low level primitives */
static void cipherstate_check_test_vectors(void) {
    /* ChaChaPoly - From Appendix A.5 of RFC 7539 */
    check_cipher(
        NOISE_CIPHER_CHACHAPOLY, 32, 16, "ChaChaPoly",
        "0x1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        /* IV is reversed compared to RFC 7539 value to correct endianness */
        0x0807060504030201, "0xf33388860000000000004e91",
        "0x496e7465726e65742d4472616674732061726520647261667420646f63756d65"
        "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
        "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
        "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
        "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
        "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
        "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
        "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
        "726573732e2fe2809d",
        "0xde06296f547214e5d6e85b1bff1602bcf76488f810f0e811efe32e094ef1cabc28537aba689788"
        "1dec5ce96fa68595394b956cda8331d7d3b1f0e13ae765282e905efde9d6e9205b29f600221b2e2a"
        "c81d807b710b7aac3c40fdc7e2e013a32f77c470984cf879a60094d3f20e572e5dca8f9d0a1ff265"
        "5e04939d741cd5dd503dd97733f9f61a3af7c2f152e096abc5f8636a093670c6d8583bdb9da65a47"
        "5678d38a46bc2860711cb3b43cb50e282342083a988501026ef330042e8f96c18fc124a827b89505"
        "974c4ae59cb5eb49f3d2e64c1194be2c3633d6418c813e8c97b5287dc5e2516770ec53862bf26cdd"
        "711bee2fc6c5f45783e825bc12872b670aa8c45057444af0d6c7",
        "0xff253f776a69ea58b8a4579cb19d78da");

    /* Test vectors for AES in GCM mode from Appendix B of:
       http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
       We can only use a few of the vectors because most of the IV's in the
       revised specification don't match what we need here */

    /* AESGCM - gcm-revised-spec.pdf, test case #13 */
    check_cipher(NOISE_CIPHER_AESGCM, 32, 16, "AESGCM",
                 "0x0000000000000000000000000000000000000000000000000000000000000000", 0,
                 "", "", "", "0x530f8afbc74536b9a963b4f1c4cb738b");

    /* AESGCM - gcm-revised-spec.pdf, test case #14 */
    check_cipher(NOISE_CIPHER_AESGCM, 32, 16, "AESGCM",
                 "0x0000000000000000000000000000000000000000000000000000000000000000", 0,
                 "", "0x00000000000000000000000000000000",
                 "0xcea7403d4d606b6e074ec5d3baf39d18",
                 "0xd0d1c8a799996bf0265b98b5d48ab919");
}

/* Check other error conditions that can be reported by the functions */
static void cipherstate_check_errors(void) {
    NoiseCipherState *state;

    /* NULL parameters in various positions */
    compare(noise_cipherstate_free(0), NOISE_ERROR_INVALID_PARAM);
    compare(noise_cipherstate_get_cipher_id(0), NOISE_CIPHER_NONE);
    compare(noise_cipherstate_get_key_length(0), 0);
    compare(noise_cipherstate_get_mac_length(0), 0);
    compare(noise_cipherstate_new_by_id(0, NOISE_HASH_BLAKE2s),
            NOISE_ERROR_INVALID_PARAM);
    compare(noise_cipherstate_new_by_name(0, "ChaChaPoly"), NOISE_ERROR_INVALID_PARAM);

    /* If the id/name is unknown, the state parameter should be set to NULL */
    state = (NoiseCipherState *) 8;
    compare(noise_cipherstate_new_by_id(&state, NOISE_HASH_BLAKE2s),
            NOISE_ERROR_UNKNOWN_ID);
    verify(state == NULL);
    state = (NoiseCipherState *) 8;
    compare(noise_cipherstate_new_by_name(&state, 0), NOISE_ERROR_INVALID_PARAM);
    verify(state == NULL);
    state = (NoiseCipherState *) 8;
    compare(noise_cipherstate_new_by_name(&state, "ChaChaPony"),
            NOISE_ERROR_UNKNOWN_NAME);
    verify(state == NULL);
}

void test_cipherstate(void) {
    cipherstate_check_test_vectors();
    cipherstate_check_errors();
}
