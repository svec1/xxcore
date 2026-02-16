#ifndef CRYPT_HPP
#define CRYPT_HPP

extern "C" {

#include <blake2/blake2b.h>
#include <blake2/blake2s.h>
#include <chacha/chacha.h>
#include <donna/poly1305-donna.h>
}

#include "utils.hpp"

class crypto {
public:
    template<std::size_t size>
    using buffer_type = noheap::buffer_bytes_type<size, noheap::ubyte>;

public:
    enum class cipher_algorithm { CHACHA20_POLY1305 = 0 };
    enum class hash_algorithm { BLAKE2s = 0, BLAKE2b };

    template<cipher_algorithm algorithm>
    static consteval std::size_t get_key_size() {
        if constexpr (algorithm == cipher_algorithm::CHACHA20_POLY1305)
            return 32;
        else
            static_assert("Unknown cipher algorithm.");
    }
    template<cipher_algorithm algorithm>
    static consteval std::size_t get_mac_size() {
        if constexpr (algorithm == cipher_algorithm::CHACHA20_POLY1305)
            return 16;
        else
            static_assert("Unknown cipher algorithm.");
    }

    template<cipher_algorithm algorithm>
    struct cipher {
        using key_type = buffer_type<get_key_size<algorithm>()>;
        using mac_type = buffer_type<get_mac_size<algorithm>()>;
    };

private:
    template<hash_algorithm _algorithm>
    struct hash_context {
        static_assert(false, "Unknown hash algorithm");
    };
    template<>
    struct hash_context<hash_algorithm::BLAKE2s> {
        using type = BLAKE2s_context_t;
    };
    template<>
    struct hash_context<hash_algorithm::BLAKE2b> {
        using type = BLAKE2b_context_t;
    };

    template<hash_algorithm algorithm>
    struct hash_state {
        using context_type = hash_context<algorithm>;
    };
    template<>
    struct hash_state<hash_algorithm::BLAKE2s> {
        using context_type = hash_context<hash_algorithm::BLAKE2s>::type;
        using buffer_type  = buffer_type<32>;

    public:
        static constexpr auto reset  = BLAKE2s_reset;
        static constexpr auto update = BLAKE2s_update;
        static constexpr auto finish = BLAKE2s_finish;
    };
    template<>
    struct hash_state<hash_algorithm::BLAKE2b> {
        using context_type = hash_context<hash_algorithm::BLAKE2b>::type;
        using buffer_type  = buffer_type<64>;

    public:
        static constexpr auto reset  = BLAKE2b_reset;
        static constexpr auto update = BLAKE2b_update;
        static constexpr auto finish = BLAKE2b_finish;
    };

public:
    constexpr crypto() = default;

public:
    template<cipher_algorithm algorithm>
    static void encrypt(std::span<noheap::ubyte> buffer, std::size_t payload_size,
                        const cipher<algorithm>::key_type &key);
    template<cipher_algorithm algorithm>
    static void decrypt(std::span<noheap::ubyte> buffer, std::size_t payload_size,
                        const cipher<algorithm>::key_type &key);

    template<hash_algorithm algorithm>
    static hash_state<algorithm>::buffer_type get_hash(std::span<noheap::byte> buffer);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("CRYPTO");

protected:
    static constexpr log_handler log{buffer_owner};
};
template<crypto::cipher_algorithm algorithm>
void crypto::encrypt(std::span<noheap::ubyte> buffer, std::size_t payload_size,
                     const cipher<algorithm>::key_type &key) {
    if constexpr (algorithm == cipher_algorithm::CHACHA20_POLY1305) {
        if (payload_size + 16 > buffer.size())
            throw noheap::runtime_error(buffer_owner, "Invalid payload size.");

        chacha_ctx       chacha_ctx{};
        poly1305_context poly_ctx{};

        chacha_keysetup(&chacha_ctx, key.data(), 256);
        poly1305_init(&poly_ctx, key.data());
        poly1305_update(&poly_ctx, buffer.data(), payload_size);

        chacha_encrypt_bytes(&chacha_ctx, buffer.data(), buffer.data(), payload_size);
        poly1305_finish(&poly_ctx, buffer.data() + payload_size);
    }
}
template<crypto::cipher_algorithm algorithm>
void crypto::decrypt(std::span<noheap::ubyte> buffer, std::size_t payload_size,
                     const cipher<algorithm>::key_type &key) {
    if constexpr (algorithm == cipher_algorithm::CHACHA20_POLY1305) {
        if (payload_size + 16 > buffer.size())
            throw noheap::runtime_error(buffer_owner, "Invalid payload size.");

        chacha_ctx       chacha_ctx{};
        poly1305_context poly_ctx{};

        chacha_keysetup(&chacha_ctx, key.data(), 256);
        chacha_encrypt_bytes(&chacha_ctx, buffer.data(), buffer.data(), payload_size);

        typename cipher<algorithm>::mac_type buffer_mac_tmp{};

        poly1305_init(&poly_ctx, key.data());
        poly1305_update(&poly_ctx, buffer.data(), payload_size);
        poly1305_finish(&poly_ctx, buffer_mac_tmp.data());

        if (!noheap::is_equal_bytes<std::uint8_t>(
                {buffer_mac_tmp.data(), buffer_mac_tmp.size()},
                {buffer.data() + payload_size, buffer_mac_tmp.size()}))
            throw noheap::runtime_error(buffer_owner, "Failure MAC.");
    }
}

template<crypto::hash_algorithm algorithm>
crypto::hash_state<algorithm>::buffer_type
    crypto::get_hash(std::span<noheap::byte> buffer) {
    using hash_state = hash_state<algorithm>;
    typename hash_state::context_type ctx;
    typename hash_state::buffer_type  buffer_tmp;

    hash_state::reset(&ctx);
    hash_state::update(&ctx, buffer.data(), buffer.size());
    hash_state::finish(&ctx, buffer_tmp.data());

    return buffer_tmp;
}

#endif
