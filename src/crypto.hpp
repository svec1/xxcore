#ifndef CRYPT_HPP
#define CRYPT_HPP

extern "C" {
#include <chacha/chacha.h>
}

#include "utils.hpp"

class crypto {
public:
    template<std::size_t size>
    using buffer_type = noheap::buffer_bytes_type<size, noheap::ubyte>;

    using buffer_iv_type = buffer_type<8>;

public:
    constexpr crypto() = default;

public:
    template<noheap::Buffer_bytes TKey>
    static void chacha_encrypt(std::span<noheap::ubyte> buffer, TKey &&key,
                               buffer_iv_type iv, std::uint64_t counter);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("CRYPTO");

protected:
    static constexpr log_handler log{buffer_owner};
};
template<noheap::Buffer_bytes TKey>
void crypto::chacha_encrypt(std::span<noheap::ubyte> buffer, TKey &&key,
                            buffer_iv_type iv, std::uint64_t counter) {
    chacha_ctx chacha_ctx{};
    chacha_keysetup(&chacha_ctx, reinterpret_cast<const noheap::ubyte *>(key.data()),
                    key.size() * 8);
    chacha_ivsetup(&chacha_ctx, iv.data(),
                   reinterpret_cast<const noheap::ubyte *>(&counter));
    chacha_encrypt_bytes(&chacha_ctx, buffer.data(), buffer.data(), buffer.size());
}

#endif
