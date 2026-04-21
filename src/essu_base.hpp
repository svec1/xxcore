#ifndef ESSU_BASE_HPP
#define ESSU_BASE_HPP

#include "network.hpp"
#include "noise.hpp"
#include "utils.hpp"

namespace essu {

constexpr std::size_t unit_size                      = 340;
constexpr std::size_t header_data_size               = 16;
constexpr std::size_t min_random_bytes_number        = 64;
constexpr std::size_t batch_units_count              = 4;
constexpr std::size_t batches_per_rekey_number       = 32;
constexpr std::size_t batches_window_number          = 16;
constexpr std::size_t max_undecrypted_batches_number = 16;
constexpr std::size_t max_available_batches_number   = 128'000;
constexpr std::size_t buffer_data_size               = unit_size - header_data_size;
constexpr std::size_t payload_data_size = buffer_data_size - min_random_bytes_number;

template<noise::noise_pattern _pattern, noise::ecdh_type _ecdh>
struct unit_config_type {
    static constexpr noise::noise_context_config<
        _pattern, _ecdh, noise::cipher_type::AESGCM, noise::hash_type::SHA3512>
        noise_config;

public:
    using noise_context_type = noise::noise_context<noise_config>;

public:
    static_assert(noise_config.pattern == noise::noise_pattern::XK
                      || noise_config.pattern == noise::noise_pattern::XK_HFS,
                  "The passed noise pattern is unavailable.");

    static_assert(noise_config.ecdh == noise::ecdh_type::X25519
                      || noise_config.ecdh == noise::ecdh_type::X25519_KYBER1024,
                  "The passed ecdh type is unavailable.");

public:
    static constexpr std::size_t hs1_size =
        noise::get_dh_key_size<noise_config.ecdh>() + noise_context_type::mac_size
        + noise::get_kem_key_size<noise_config.ecdh>();
    static constexpr std::size_t hs2_size =
        noise::get_dh_key_size<noise_config.ecdh>()
        + noise::get_kem_cipher_text_size<noise_config.ecdh>()
        + noise_context_type::mac_size;
    static constexpr std::size_t hs3_size = noise::get_dh_key_size<noise_config.ecdh>()
                                            + noise_context_type::handshake_payload_size
                                            + noise_context_type::mac_size * 2;
};

using base_unit_config_type =
    unit_config_type<noise::noise_pattern::XK, noise::ecdh_type::X25519>;

// Transport unit
struct unit_type {
    using config_type        = base_unit_config_type;
    using noise_context_type = config_type::noise_context_type;

public:
    enum class payload_type : noheap::ubyte {
        session_request = 0,
        session_created,
        session_confirmed,
        retry,
        token_request,
        hole_punch,
        data,
    };
    enum class flag_type : noheap::ubyte {
        none = 0,
        wait_next,
        drop, // Dummy unit
    };

public:
    struct header_data_type {
        std::uint64_t number;
        std::uint32_t key_iteration_number;
        payload_type  type;
        flag_type     flag;
        // Reserved
        std::uint8_t byte1;
        std::uint8_t byte2;
    };

public:
    static constexpr std::size_t buffer_size_without_mac =
        buffer_data_size - noise_context_type::mac_size;

public:
    static_assert(sizeof(header_data_type) == header_data_size,
                  "Header size is invalid.");

public:
    header_data_type header{};

    noheap::buffer_bytes_type<buffer_data_size, noheap::rbyte> buffer{};
};

// Packet(Batch)
struct extention_payload_data_type {
    noheap::buffer_type<unit_type, batch_units_count> units;
};
struct noise_handshake_context;
struct session_info_type;
struct protocol_type;
using packet_type = network::packet_native_type<extention_payload_data_type>;

} // namespace essu
#endif
