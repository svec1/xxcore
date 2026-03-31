#ifndef ESSU_HPP
#define ESSU_HPP

#include "network.hpp"
#include "noise.hpp"
#include "utils.hpp"

namespace essu {

static constexpr std::size_t unit_size        = 340;
static constexpr std::size_t header_data_size = 16;
static constexpr std::size_t buffer_data_size = unit_size - header_data_size;

static constexpr std::size_t batch_units_count   = 4;
static constexpr std::size_t number_units_window = 64; // 16 batch

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
                      || noise_config.ecdh == noise::ecdh_type::x448
                      || noise_config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024
                      || noise_config.ecdh == noise::ecdh_type::x448_hybrid_kyber1024,
                  "The passed ecdh type is unavailable.");

private:
    static consteval std::size_t get_hs1_size() {
        if constexpr (noise_config.ecdh == noise::ecdh_type::x25519
                      || noise_config.ecdh == noise::ecdh_type::x448)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else if constexpr (noise_config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024
                           || noise_config.ecdh
                                  == noise::ecdh_type::x448_hybrid_kyber1024)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise::get_kem_key_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else
            static_assert(false, "Unreachable.");
    }
    static consteval std::size_t get_hs2_size() {
        if constexpr (noise_config.ecdh == noise::ecdh_type::x25519
                      || noise_config.ecdh == noise::ecdh_type::x448)
            return noise::get_dh_key_size<noise_config.ecdh>()
                   + noise_context_type::mac_size;
        else if constexpr (noise_config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024
                           || noise_config.ecdh
                                  == noise::ecdh_type::x448_hybrid_kyber1024)
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

template<typename T>
concept Unit_config_type =
    std::same_as<std::decay_t<T>, unit_config_type<std::decay_t<T>::noise_config.pattern,
                                                   std::decay_t<T>::noise_config.ecdh,
                                                   std::decay_t<T>::payload_data_size>>;

// Transport unit
template<Unit_config_type _config_type>
struct unit_type {
    using config_type        = _config_type;
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
        std::size_t unit_number;

        noheap::buffer_bytes_type<6> reserved;

        flag_type    flag;
        payload_type type;
    };

public:
    static constexpr std::size_t get_buffer_size_without_mac() {
        return noheap::buffer_size<decltype(buffer)> - noise_context_type::mac_size;
    }

public:
    static_assert(sizeof(header_data_type) == header_data_size,
                  "Header size is invalid.");
    static_assert(config_type::payload_data_size <= get_buffer_size_without_mac(),
                  "Unexpected size of payload data.");

public:
    header_data_type header{};

    noheap::buffer_bytes_type<buffer_data_size, noheap::rbyte> buffer{};
};

// Packet(Batch)
template<Unit_config_type _config_type>
struct extention_payload_data_type {
    using unit_type = unit_type<_config_type>;

public:
    noheap::buffer_type<unit_type, batch_units_count> units;
};

template<Unit_config_type _config_type>
using packet_type =
    network::packet_native_type<extention_payload_data_type<_config_type>>;

template<Unit_config_type _config_type>
struct protocol_type;

template<Unit_config_type _config_type>
struct session_info_type {
    using packet_type        = packet_type<_config_type>;
    using unit_type          = packet_type::extention_data_type::unit_type;
    using noise_context_type = unit_type::noise_context_type;

    friend class protocol_type<_config_type>;

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

    typename noise_context_type::cipher_state payload_cipher_state{};
    typename noise_context_type::dh_key_type  header_obfs_key{};

private:
    status_type status               = status_type::UNCONNECTED;
    std::size_t sender_unit_number   = 0;
    std::size_t receiver_unit_number = 0;
};

template<Unit_config_type _config_type>
struct protocol_type
    : public network::protocol_native_type<
          packet_type<_config_type>, noheap::log_impl::create_owner("ESSU_PROTOCOL")> {
    using session_info_type  = session_info_type<_config_type>;
    using packet_type        = session_info_type::packet_type;
    using unit_type          = session_info_type::unit_type;
    using noise_context_type = session_info_type::noise_context_type;

    static constexpr std::size_t timeout_ms = 2500;

public:
    using session_info_s_type =
        noheap::monotonic_array<session_info_type *, network::max_count_addresses>;

public:
    constexpr void prepare(packet_type &pckt, network::buffer_address_type addr,
                           protocol_type::callback_prepare_type callback) const override {
        try {
            auto session_info_it = find_session_info(addr);
            if (session_info_it == session_info_s.end())
                throw noheap::runtime_error("Not found session info.");
            decltype(auto) session_info = *(*session_info_it);

            typename noise_context_type::cipher_state header_cipher_state;
            header_cipher_state.set_key(session_info.header_obfs_key);

            callback(pckt);
            update_protocol_status(session_info, pckt->units[0]);

            for (std::size_t i = 0; i < pckt->units.size(); ++i) {
                unit_type &unit = pckt->units[i];

                unit.header.unit_number = session_info.sender_unit_number++;

                // Adds random padding
                {
                    // Determines payload size of the unit to define size of random
                    // padding
                    std::size_t payload_data_size = unit.get_buffer_size_without_mac();
                    if (unit.header.type == unit_type::payload_type::session_request)
                        payload_data_size = unit_type::config_type::hs1_size;
                    else if (unit.header.type == unit_type::payload_type::session_created)
                        payload_data_size = unit_type::config_type::hs2_size;
                    else if (unit.header.type
                             == unit_type::payload_type::session_confirmed)
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
                        std::clamp<std::size_t>(payload_data_size, 0,
                                                unit.buffer.size()));
                    session_info.payload_cipher_state.pad();
                }

                // Encrypts buffer data and authenticates based on the header
                if (unit.header.type == unit_type::payload_type::data) {
                    session_info.payload_cipher_state.input_buffer.set(
                        {unit.buffer.data(), unit.buffer.size()},
                        unit.get_buffer_size_without_mac());
                    session_info.payload_cipher_state.set_encrypt_nonce(
                        unit.header.unit_number);
                    session_info.payload_cipher_state.encrypt(
                        {reinterpret_cast<noheap::rbyte *>(&unit.header),
                         sizeof(unit.header)});
                    session_info.payload_cipher_state.rekey_encrypt();
                }

                // Generates header obfuscation key based on the unit_number
                noise::buffer_type<sizeof(unit.header) + noise_context_type::mac_size>
                    obfs_key_tmp{};
                header_cipher_state.input_buffer.set(
                    {obfs_key_tmp.data(), obfs_key_tmp.size()},
                    obfs_key_tmp.size() - noise_context_type::mac_size);
                header_cipher_state.set_encrypt_nonce(unit.header.unit_number);
                header_cipher_state.encrypt({});

                // Adds header data obfuscation
                std::transform(
                    reinterpret_cast<noheap::rbyte *>(&unit.header),
                    reinterpret_cast<noheap::rbyte *>(&unit.header) + sizeof(unit.header),
                    obfs_key_tmp.data(), reinterpret_cast<noheap::rbyte *>(&unit.header),
                    std::bit_xor{});
            }

            // Shuffle units in batch
            std::random_device rd;
            std::mt19937       generator(rd());
            std::shuffle(pckt->units.begin(), pckt->units.end(), generator);

        } catch (noheap::runtime_error &excp) {
            excp.set_owner(this->buffer_owner);
            throw;
        }
    }
    constexpr void handle(packet_type &pckt, network::buffer_address_type addr,
                          protocol_type::callback_handle_type callback) const override {
        try {
            auto session_info_it = find_session_info(addr);
            if (session_info_it == session_info_s.end())
                return;

            decltype(auto) session_info = *(*session_info_it);

            typename noise_context_type::cipher_state header_cipher_state;
            header_cipher_state.set_key(session_info.header_obfs_key);

            // Selects possible unit number
            std::size_t count_decrypted_units = 0;
            for (std::size_t possible_unit_number = session_info.receiver_unit_number;
                 possible_unit_number
                 < session_info.receiver_unit_number + number_units_window;
                 ++possible_unit_number) {
                // Generates header obfuscation key based on the possible_unit_number
                noise::buffer_type<sizeof(pckt->units[0].header)
                                   + noise_context_type::mac_size>
                    obfs_key_tmp{};
                header_cipher_state.input_buffer.set(
                    {obfs_key_tmp.data(), obfs_key_tmp.size()},
                    obfs_key_tmp.size() - noise_context_type::mac_size);
                header_cipher_state.set_encrypt_nonce(possible_unit_number);
                header_cipher_state.encrypt({});

                for (auto &unit : pckt->units) {
                    unit_type test_unit = unit;

                    // Deletes header data obfuscation
                    std::transform(reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                                   reinterpret_cast<noheap::rbyte *>(&test_unit.header)
                                       + sizeof(test_unit.header),
                                   obfs_key_tmp.data(),
                                   reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                                   std::bit_xor{});

                    if (test_unit.header.unit_number != possible_unit_number)
                        continue;

                    if (test_unit.header.type == unit_type::payload_type::data) {
                        // Tries to decrypt buffer data
                        session_info.payload_cipher_state.output_buffer.set(
                            {test_unit.buffer.data(), test_unit.buffer.size()},
                            test_unit.buffer.size());
                        session_info.payload_cipher_state.set_decrypt_nonce(
                            test_unit.header.unit_number);
                        try {
                            session_info.payload_cipher_state.decrypt(
                                {reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                                 sizeof(test_unit.header)});
                        } catch (noheap::runtime_error &) {
                            continue;
                        }
                        session_info.payload_cipher_state.rekey_decrypt();
                    }

                    unit = test_unit;
                    ++count_decrypted_units;
                    break;
                }

                if (count_decrypted_units == pckt->units.size())
                    break;
            }

            // If it was not possible to decrypt all units in batch
            if (count_decrypted_units != pckt->units.size())
                throw noheap::runtime_error("Failed to decrypt packet.{}",
                                            count_decrypted_units);

            // Restores order of units in batch
            std::sort(pckt->units.begin(), pckt->units.end(),
                      [](const auto &el_left, const auto &el_right) {
                          return el_left.header.unit_number < el_right.header.unit_number;
                      });

            session_info.receiver_unit_number =
                pckt->units[pckt->units.size() - 1].header.unit_number + 1;

            update_protocol_status(session_info, pckt->units[0]);

            callback(std::move(pckt));
        } catch (noheap::runtime_error &excp) {
            excp.set_owner(this->buffer_owner);
            throw;
        }
    };

public:
    void register_session_info(session_info_type &session_info) const {
        if (find_session_info(session_info.addr) != session_info_s.end())
            throw noheap::runtime_error(this->buffer_owner, "Session already exist.");
        if (session_info_s.size() == network::max_count_addresses)
            throw noheap::runtime_error(this->buffer_owner,
                                        "Sessions limit has been reached.");

        const_cast<session_info_s_type &>(session_info_s).push_back(&session_info);
    }
    void set_starting_handshake(session_info_type &session_info) const {
        session_info.status = session_info_type::status_type::HS1;
    }
    void set_initial_unit_number(session_info_type &session_info,
                                 std::uint32_t      initial_sender_unit_number,
                                 std::uint32_t      initial_receiver_unit_number) const {
        session_info.sender_unit_number   = initial_sender_unit_number;
        session_info.receiver_unit_number = initial_receiver_unit_number;
    }

private:
    session_info_s_type::iterator
        find_session_info(network::buffer_address_type addr) const {
        return std::find_if(
            session_info_s.begin(), session_info_s.end(), [&](const auto &el) {
                return noheap::is_equal_bytes(
                    {reinterpret_cast<const noheap::ubyte *>(el->addr.data()),
                     el->addr.size()},
                    {reinterpret_cast<const noheap::ubyte *>(addr.data()), addr.size()});
            });
    }
    void update_protocol_status(session_info_type &session_info,
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

private:
    mutable session_info_s_type session_info_s;
};

// Noise handshake action for establishing shared secret key
template<Unit_config_type _config_type>
struct noise_handshake_action : public network::action<packet_type<_config_type>> {
public:
    using packet_type        = noise_handshake_action::packet_type;
    using unit_type          = packet_type::extention_data_type::unit_type;
    using noise_context_type = unit_type::noise_context_type;

public:
    constexpr void init_packet(packet_type &pckt) override {
        check_noise_action(noise::noise_action::WRITE_MESSAGE);

        auto &payload_unit = pckt->units[0];

        // Gets noise message
        if (!fragmentation) {
            // Generates random value
            if (number_handshake_parts == 2) {
                noise_handshake_payload =
                    noheap::to_buffer<std::decay_t<decltype(noise_handshake_payload)>>(
                        noheap::get_random_bytes<
                            noheap::buffer_size<decltype(noise_handshake_payload)>>());
                noise_ctx.get_handshake_payload_buffer().set(
                    {noise_handshake_payload.data(), noise_handshake_payload.size()},
                    noise_handshake_payload.size());
            }

            noise_ctx.get_handshake_buffer().set(
                {noise_handshake_packet.data(), noise_handshake_packet.size()}, 0);
            noise_ctx.set_handshake_message();

            // Adds ephemeral key obfuscation on ephemeral key
            if (number_handshake_parts == 0) {
                std::transform(noise_handshake_packet.begin(),
                               noise_handshake_packet.begin() + ephemeral_obfs_key.size(),
                               ephemeral_obfs_key.data(), noise_handshake_packet.begin(),
                               std::bit_xor{});
            }
        }

        // Copy payload of the noise message
        std::copy(noise_handshake_packet.begin() + offset_noise_handshake_unit,
                  noise_handshake_packet.begin() + offset_noise_handshake_unit
                      + payload_unit.buffer.size(),
                  reinterpret_cast<noheap::rbyte *>(payload_unit.buffer.begin()));
        offset_noise_handshake_unit += payload_unit.buffer.size();

        // Determines type of payload data
        if (number_handshake_parts == 0)
            payload_unit.header.type = unit_type::payload_type::session_request;
        else if (number_handshake_parts == 1)
            payload_unit.header.type = unit_type::payload_type::session_created;
        else if (number_handshake_parts == 2)
            payload_unit.header.type = unit_type::payload_type::session_confirmed;

        // If fragmentation
        if (offset_noise_handshake_unit < noise_ctx.get_handshake_buffer().get().size) {
            payload_unit.header.flag = decltype(payload_unit.header.flag)::wait_next;
            fragmentation            = true;
            return;
        }

        payload_unit.header.flag    = decltype(payload_unit.header.flag)::none;
        noise_handshake_packet      = {};
        offset_noise_handshake_unit = 0;
        fragmentation               = false;

        ++number_handshake_parts;
    }
    constexpr void process_packet(packet_type &&pckt) override {
        check_noise_action(noise::noise_action::READ_MESSAGE);

        auto &payload_unit = pckt->units[0];
        if (payload_unit.header.flag == decltype(payload_unit.header.flag)::drop)
            throw noheap::runtime_error("Noise handshake dropped.");

        // Determines size of payload data
        std::size_t payload_data_size;
        if (number_handshake_parts == 0)
            payload_data_size = unit_type::config_type::hs1_size;
        else if (number_handshake_parts == 1)
            payload_data_size = unit_type::config_type::hs2_size;
        else if (number_handshake_parts == 2)
            payload_data_size = unit_type::config_type::hs3_size;

        // Copies accepted unit to buffer of noise handshake message
        std::copy(payload_unit.buffer.begin(), payload_unit.buffer.end(),
                  noise_handshake_packet.begin() + offset_noise_handshake_unit);
        offset_noise_handshake_unit += payload_data_size;

        // If fragmentation
        if (payload_data_size >= payload_unit.buffer.size()
            && payload_unit.header.flag == decltype(payload_unit.header.flag)::wait_next)
            return;

        if (number_handshake_parts == 0)
            // Deletes ephemeral key obfuscation
            std::transform(noise_handshake_packet.begin(),
                           noise_handshake_packet.begin() + ephemeral_obfs_key.size(),
                           ephemeral_obfs_key.begin(), noise_handshake_packet.begin(),
                           std::bit_xor{});
        else if (number_handshake_parts == 2)
            // Sets buffer to get random value
            noise_ctx.get_handshake_payload_buffer().set(
                {noise_handshake_payload.data(), noise_handshake_payload.size()}, 0);

        // Sets noise message
        noise_ctx.get_handshake_buffer().set(
            {noise_handshake_packet.data(), offset_noise_handshake_unit},
            payload_data_size);
        noise_ctx.get_handshake_message();

        noise_handshake_packet      = {};
        offset_noise_handshake_unit = 0;
        ++number_handshake_parts;
    }

public:
    noise::noise_action get_action() {
        return fragmentation ? noise::noise_action::WRITE_MESSAGE
                             : noise_ctx.get_action();
    }
    typename noise_context_type::buffer_handshake_payload_type get_handshake_payload() {
        return noise_handshake_payload;
    }
    typename noise_context_type::hash_state::buffer_type get_handshake_hash() {
        return noise_handshake_hash;
    }

public:
    void init(noise::noise_role role, noise_context_type::prologue_extention_type ext,
              const noise_context_type::keypair_type        &local_keypair,
              const noise_context_type::dh_key_type         &remote_public_key,
              const noise_context_type::pre_shared_key_type &pre_shared_key,
              const noise_context_type::dh_key_type         &_ephemeral_obfs_key) {
        // Init noise context
        noise_ctx.init(role);
        noise_ctx.set_prologue(ext);

        noise_ctx.set_local_keypair(local_keypair);
        noise_ctx.set_remote_public_key(remote_public_key);
        noise_ctx.set_pre_shared_key(pre_shared_key);

        noise_ctx.start();

        ephemeral_obfs_key = _ephemeral_obfs_key;

        number_handshake_parts      = 0;
        offset_noise_handshake_unit = 0;
        fragmentation               = false;
    }
    noise_context_type::cipher_state dump() {
        noise_ctx.stop();

        noise_handshake_hash  = noise_ctx.get_handshake_hash();
        auto cipher_state_tmp = noise_ctx.get_cipher_state();
        noise_ctx.dump();

        return cipher_state_tmp;
    }

private:
    void check_noise_action(noise::noise_action expected) {
        auto action = noise_ctx.get_action();
        if (action == noise::noise_action::FAILED)
            throw noheap::runtime_error("Failed to handshake.");
        else if (number_handshake_parts > 2)
            throw noheap::runtime_error(
                "Unexpected behaviour during the noise handshake.");

        if (action == expected)
            return;

        if (action == noise::noise_action::WRITE_MESSAGE)
            throw noheap::runtime_error("Expected message to be sent.");
        else if (action == noise::noise_action::READ_MESSAGE)
            throw noheap::runtime_error("Expected message to be received.");
        else
            throw noheap::runtime_error("Handshake already completed.");
    }

private:
    noise_context_type noise_ctx;
    std::size_t        number_handshake_parts;

    typename noise_context_type::buffer_handshake_packet_type noise_handshake_packet{};
    noise_context_type::dh_key_type                           ephemeral_obfs_key;
    std::size_t                                               offset_noise_handshake_unit;
    bool                                                      fragmentation;

    typename noise_context_type::buffer_handshake_payload_type noise_handshake_payload;
    typename noise_context_type::hash_state::buffer_type       noise_handshake_hash;
};

} // namespace essu

#endif
