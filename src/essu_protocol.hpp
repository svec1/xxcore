#ifndef ESSU_HPP
#define ESSU_HPP

#include "network.hpp"
#include "noise.hpp"
#include "utils.hpp"

namespace essu {

static constexpr std::size_t unit_size        = 340;
static constexpr std::size_t header_data_size = 16;
static constexpr std::size_t buffer_data_size = unit_size - header_data_size;

static constexpr std::size_t batch_units_count              = 4;
static constexpr std::size_t batches_per_rekey_number       = 32;
static constexpr std::size_t batches_window_number          = 16;
static constexpr std::size_t max_undecrypted_batches_number = 16;

template<noise::noise_pattern _pattern, noise::ecdh_type _ecdh,
         std::size_t _payload_data_size>
struct unit_config_type {
    static constexpr noise::noise_context_config<_pattern, _ecdh> noise_config;
    static constexpr std::size_t payload_data_size = _payload_data_size;

public:
    using noise_context_type = noise::noise_context<noise_config>;

public:
    static_assert(noise_config.pattern == noise::noise_pattern::XK
                      || noise_config.pattern == noise::noise_pattern::XK_HFS,
                  "The passed noise pattern is unavailable.");

    static_assert(noise_config.ecdh == noise::ecdh_type::x25519

                      || noise_config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024,
                  "The passed ecdh type is unavailable.");

private:
    static consteval std::size_t get_hs1_size() {
        if constexpr (noise_config.ecdh == noise::ecdh_type::x25519)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else if constexpr (noise_config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise::get_kem_key_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else
            static_assert(false, "Unreachable.");
    }
    static consteval std::size_t get_hs2_size() {
        if constexpr (noise_config.ecdh == noise::ecdh_type::x25519)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else if constexpr (noise_config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise::get_kem_cipher_text_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else
            static_assert(false, "Unreachable.");
    }
    static consteval std::size_t get_hs3_size() {
        return noise::get_dh_key_size<noise_config.ecdh>()
               + noise_context_type::handshake_payload_size
               + noise_context_type::mac_size * 2;
    }

public:
    static constexpr std::size_t hs1_size = get_hs1_size();
    static constexpr std::size_t hs2_size = get_hs2_size();
    static constexpr std::size_t hs3_size = get_hs3_size();
};

using base_unit_config_type =
    unit_config_type<noise::noise_pattern::XK, noise::ecdh_type::x25519, 280>;

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
        std::size_t   number;
        std::uint32_t key_iteration;
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
    static_assert(config_type::payload_data_size <= buffer_size_without_mac,
                  "Unexpected size of payload data.");

public:
    header_data_type header{};

    noheap::buffer_bytes_type<buffer_data_size, noheap::rbyte> buffer{};
};

// Packet(Batch)
struct extention_payload_data_type {
    noheap::buffer_type<unit_type, batch_units_count> units;
};

using packet_type = network::packet_native_type<extention_payload_data_type>;

struct protocol_type;

struct session_info_type {
    using noise_context_type = unit_type::noise_context_type;

    friend class protocol_type;

private:
    enum class status_type : std::size_t {
        UNCONNECTED = 0,
        HS1,
        HS2,
        HS3,
        CONNECTED,
    };

public:
    session_info_type(network::buffer_address_type _addr) : addr(_addr) {}

public:
    const network::buffer_address_type addr;

private:
    typename noise_context_type::cipher_state payload_cipher_state{};
    typename noise_context_type::cipher_state header_cipher_state{};

    status_type status                  = status_type::UNCONNECTED;
    std::size_t batches_sent_number     = 0;
    std::size_t sender_units_number     = 0;
    std::size_t receiver_units_number   = 0;
    std::size_t sender_key_iteration    = 0;
    std::size_t receiver_key_iteration  = 0;
    std::size_t count_undecrypted_batch = 0;
};

struct protocol_type
    : public network::protocol_native_type<packet_type, noheap::log_impl::create_owner(
                                                            "ESSU_PROTOCOL")> {
    using noise_context_type = session_info_type::noise_context_type;

    static constexpr std::size_t timeout_ms = 2500;

public:
    using session_info_s_type =
        noheap::monotonic_array<session_info_type *, network::max_count_addresses>;

public:
    void prepare(packet_type &pckt, network::buffer_address_type addr,
                 protocol_type::callback_prepare_type callback) const;
    void handle(packet_type &pckt, network::buffer_address_type addr,
                protocol_type::callback_handle_type callback) const;

public:
    void register_session_info(session_info_type &session_info) const;
    void set_starting_handshake(session_info_type &session_info) const;
    void set_payload_cipher_state(
        session_info_type                 &session_info,
        noise_context_type::cipher_state &&payload_cipher_state) const;
    void set_header_obfs_key(session_info_type              &session_info,
                             noise_context_type::dh_key_type header_obfs_key) const;
    void set_initial_units_number(session_info_type &session_info,
                                  std::uint32_t      initial_sender_units_number,
                                  std::uint32_t      initial_receiver_units_number) const;

private:
    session_info_s_type::iterator
         find_session_info(network::buffer_address_type addr) const;
    void update_protocol_status(session_info_type &session_info,
                                const unit_type   &unit) const;
    noise::buffer_type<sizeof(typename unit_type::header_data_type)>
        derive_header_obfs_key(
            typename noise_context_type::cipher_state &header_cipher_state,
            std::uint32_t                              number) const;

private:
    mutable session_info_s_type session_info_s;
};

} // namespace essu

void essu::protocol_type::prepare(packet_type &pckt, network::buffer_address_type addr,
                                  protocol_type::callback_prepare_type callback) const {
    try {
        auto session_info_it = find_session_info(addr);
        if (session_info_it == session_info_s.end())
            throw noheap::runtime_error("Not found session info.");
        decltype(auto) session_info = *(*session_info_it);

        callback(pckt);
        update_protocol_status(session_info, pckt->units[0]);

        // Performs rekey for encryption
        ++session_info.batches_sent_number;
        if (session_info.payload_cipher_state.valid()
            && session_info.batches_sent_number % batches_per_rekey_number == 0) {
            session_info.payload_cipher_state.rekey_encrypt();
            ++session_info.sender_key_iteration;
        }

        for (std::size_t i = 0; i < pckt->units.size(); ++i) {
            unit_type &unit = pckt->units[i];

            unit.header.number        = session_info.sender_units_number++;
            unit.header.key_iteration = session_info.sender_key_iteration;

            // Adds random padding
            {
                // Determines payload size of the unit to define size of random
                // padding
                std::size_t payload_data_size = unit.buffer_size_without_mac;
                if (unit.header.type == unit_type::payload_type::session_request)
                    payload_data_size = unit_type::config_type::hs1_size;
                else if (unit.header.type == unit_type::payload_type::session_created)
                    payload_data_size = unit_type::config_type::hs2_size;
                else if (unit.header.type == unit_type::payload_type::session_confirmed)
                    payload_data_size = unit_type::config_type::hs3_size;
                else if (unit.header.type == unit_type::payload_type::data)
                    payload_data_size = unit_type::config_type::payload_data_size;
                else
                    payload_data_size = 0;

                // Dummy unit
                if (unit.header.flag == unit_type::flag_type::drop || i >= 2)
                    payload_data_size = 0;

                // Adds random padding after payload data
                session_info.payload_cipher_state.input_buffer.set(
                    {reinterpret_cast<noheap::rbyte *>(unit.buffer.data()),
                     unit.buffer.size()},
                    std::clamp<std::size_t>(payload_data_size, 0, unit.buffer.size()));
                session_info.payload_cipher_state.pad();
            }

            // Encrypts buffer data and authenticates based on the header
            if (unit.header.type == unit_type::payload_type::data) {
                session_info.payload_cipher_state.input_buffer.set(
                    {unit.buffer.data(), unit.buffer.size()},
                    unit.buffer_size_without_mac);
                session_info.payload_cipher_state.set_encrypt_nonce(unit.header.number);
                session_info.payload_cipher_state.encrypt(
                    {reinterpret_cast<noheap::rbyte *>(&unit.header),
                     sizeof(unit.header)});
            }

            // Generates header obfuscation key based on the unit_number
            auto obfs_key_tmp = derive_header_obfs_key(session_info.header_cipher_state,
                                                       unit.header.number);

            // Adds header data obfuscation
            std::transform(
                reinterpret_cast<noheap::rbyte *>(&unit.header),
                reinterpret_cast<noheap::rbyte *>(&unit.header) + sizeof(unit.header),
                obfs_key_tmp.data(), reinterpret_cast<noheap::rbyte *>(&unit.header),
                std::bit_xor{});
        }

        // Shuffles units in batch
        std::random_device rd;
        std::mt19937       generator(rd());
        std::shuffle(pckt->units.begin(), pckt->units.end(), generator);

    } catch (noheap::runtime_error &excp) {
        excp.set_owner(this->buffer_owner);
        throw;
    }
}

void essu::protocol_type::handle(packet_type &pckt, network::buffer_address_type addr,
                                 protocol_type::callback_handle_type callback) const {
    try {
        auto session_info_it = find_session_info(addr);
        if (session_info_it == session_info_s.end())
            return;

        decltype(auto) session_info = *(*session_info_it);

        // Selects possible unit number
        std::size_t count_decrypted_units = 0;
        for (std::size_t possible_unit_number = session_info.receiver_units_number;
             possible_unit_number
             < session_info.receiver_units_number + batches_window_number;
             ++possible_unit_number) {
            // Generates header obfuscation key based on the possible_unit_number
            auto obfs_key_tmp = derive_header_obfs_key(session_info.header_cipher_state,
                                                       possible_unit_number);
            for (auto &unit : pckt->units) {
                unit_type test_unit = unit;

                // Deletes header data obfuscation
                std::transform(reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                               reinterpret_cast<noheap::rbyte *>(&test_unit.header)
                                   + sizeof(test_unit.header),
                               obfs_key_tmp.data(),
                               reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                               std::bit_xor{});

                if (test_unit.header.number != possible_unit_number)
                    continue;

                for (;
                     session_info.receiver_key_iteration < test_unit.header.key_iteration;
                     ++session_info.receiver_key_iteration)
                    session_info.payload_cipher_state.rekey_decrypt();

                if (test_unit.header.type == unit_type::payload_type::data) {
                    // Tries to decrypt buffer data
                    session_info.payload_cipher_state.output_buffer.set(
                        {test_unit.buffer.data(), test_unit.buffer.size()},
                        test_unit.buffer.size());
                    session_info.payload_cipher_state.set_decrypt_nonce(
                        test_unit.header.number);
                    try {
                        session_info.payload_cipher_state.decrypt(
                            {reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                             sizeof(test_unit.header)});
                    } catch (noheap::runtime_error &excp) {
                        continue;
                    }
                }

                unit = test_unit;
                ++count_decrypted_units;
                break;
            }

            if (count_decrypted_units == pckt->units.size())
                break;
        }

        // If it was not possible to decrypt all units in batch
        if (count_decrypted_units != pckt->units.size()) {
            ++session_info.count_undecrypted_batch;
            if (session_info.count_undecrypted_batch == max_undecrypted_batches_number)
                throw noheap::runtime_error("Failed to decrypt last batches.");
            return;
        } else
            session_info.count_undecrypted_batch = 0;

        // Restores order of units in batch
        std::sort(pckt->units.begin(), pckt->units.end(),
                  [](const auto &el_left, const auto &el_right) {
                      return el_left.header.number < el_right.header.number;
                  });

        session_info.receiver_units_number =
            pckt->units[pckt->units.size() - 1].header.number + 1;

        update_protocol_status(session_info, pckt->units[0]);

        callback(std::move(pckt));
    } catch (noheap::runtime_error &excp) {
        excp.set_owner(this->buffer_owner);
        throw;
    }
};

void essu::protocol_type::register_session_info(session_info_type &session_info) const {
    if (find_session_info(session_info.addr) != session_info_s.end())
        throw noheap::runtime_error(this->buffer_owner, "Session already exist.");
    if (session_info_s.size() == network::max_count_addresses)
        throw noheap::runtime_error(this->buffer_owner,
                                    "Sessions limit has been reached.");

    const_cast<session_info_s_type &>(session_info_s).push_back(&session_info);
}
void essu::protocol_type::set_starting_handshake(session_info_type &session_info) const {
    session_info.status = session_info_type::status_type::HS1;
}
void essu::protocol_type::set_payload_cipher_state(
    session_info_type                 &session_info,
    noise_context_type::cipher_state &&payload_cipher_state) const {
    session_info.payload_cipher_state = std::move(payload_cipher_state);
}
void essu::protocol_type::set_header_obfs_key(
    session_info_type              &session_info,
    noise_context_type::dh_key_type header_obf_key) const {
    session_info.header_cipher_state.set_key(header_obf_key);
}
void essu::protocol_type::set_initial_units_number(
    session_info_type &session_info, std::uint32_t initial_sender_unit_number,
    std::uint32_t initial_receiver_unit_number) const {
    session_info.sender_units_number   = initial_sender_unit_number;
    session_info.receiver_units_number = initial_receiver_unit_number;
}

essu::protocol_type::session_info_s_type::iterator
    essu::protocol_type::find_session_info(network::buffer_address_type addr) const {
    return std::find_if(
        session_info_s.begin(), session_info_s.end(), [&](const auto &el) {
            return noheap::is_equal_bytes(
                {reinterpret_cast<const noheap::ubyte *>(el->addr.data()),
                 el->addr.size()},
                {reinterpret_cast<const noheap::ubyte *>(addr.data()), addr.size()});
        });
}
void essu::protocol_type::update_protocol_status(session_info_type &session_info,
                                                 const unit_type   &unit) const {
    if (session_info.status == session_info_type::status_type::UNCONNECTED)
        return;
    else if (session_info.status == session_info_type::status_type::HS1
             && unit.header.type != unit_type::payload_type::session_request)
        throw noheap::runtime_error("Expected session request unit.");
    else if (session_info.status == session_info_type::status_type::HS2
             && unit.header.type != unit_type::payload_type::session_created)
        throw noheap::runtime_error("Expected session created unit.");
    else if (session_info.status == session_info_type::status_type::HS3
             && unit.header.type != unit_type::payload_type::session_confirmed)
        throw noheap::runtime_error("Expected session confirmed unit.");
    else if (session_info.status == session_info_type::status_type::CONNECTED
             && unit.header.type != unit_type::payload_type::data)
        throw noheap::runtime_error("Expected unit to contain payload data.");
    else
        session_info.status = typename session_info_type::status_type(
            static_cast<std::size_t>(session_info.status) + 1);
}
noise::buffer_type<sizeof(typename essu::unit_type::header_data_type)>
    essu::protocol_type::derive_header_obfs_key(
        typename noise_context_type::cipher_state &header_cipher_state,
        std::uint32_t                              number) const {
    noise::buffer_type<sizeof(typename essu::unit_type::header_data_type)
                       + noise_context_type::mac_size>
        obfs_key_tmp{};
    header_cipher_state.input_buffer.set({obfs_key_tmp.data(), obfs_key_tmp.size()},
                                         obfs_key_tmp.size()
                                             - noise_context_type::mac_size);
    header_cipher_state.set_encrypt_nonce(number);
    header_cipher_state.encrypt({});

    return noheap::to_buffer<decltype(derive_header_obfs_key(header_cipher_state,
                                                             number))>(obfs_key_tmp);
}

#endif
