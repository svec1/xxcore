#ifndef ESSU_HPP
#define ESSU_HPP

#include "crypto.hpp"
#include "network.hpp"
#include "noise.hpp"
#include "utils.hpp"

namespace essu {
static constexpr std::size_t termination_timeout_ms = 3000;

static constexpr std::size_t packet_size                     = 340;
static constexpr std::size_t batch_packets_count             = 4;
static constexpr std::size_t batch_max_payload_packets_count = 2;
static constexpr std::size_t batch_old_packets_count         = 2;
static constexpr std::size_t max_node_connection             = 4;
static constexpr std::size_t max_node_buffered_packets       = 255;

struct transport_data_config {
    noise::ecdh_type ecdh;
    std::size_t      payload_data_size;
};

template<transport_data_config config>
struct transport_data_type {
    using noise_context_type = noise::noise_context<config.ecdh>;

public:
    enum class payload_type : noheap::ubyte {
        session_request = 0,
        session_created,
        session_confirmed,
        data,
        retry,
        token_request,
        hole_punch,
    };
    enum class flag_type : noheap::ubyte {
        none = 0,
        wait_next, // Waiting next packet(for fragmentation)
        drop,      // Dummy packet
    };

public:
    struct ack_data_type {
        std::uint64_t ranges;
        std::uint16_t ack_through;
        std::uint16_t acnt;
    };
    struct header_data_type {
        ack_data_type ack;
        std::uint16_t destination_id;
        std::uint16_t source_id;
        std::uint16_t packet_number;
        flag_type     flag;
        payload_type  type;
    };

public:
    static constexpr transport_data_config get_config() { return config; }
    static constexpr std::size_t           get_buffer_size() {
        return packet_size - sizeof(header_data_type);
    }
    static constexpr std::size_t get_session_request_size() {
        if constexpr (config.ecdh == noise::ecdh_type::x25519
                      || config.ecdh == noise::ecdh_type::x448)
            return noise::get_dh_key_size<config.ecdh>();
        else if constexpr (config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024
                           || config.ecdh == noise::ecdh_type::x448_hybrid_kyber1024)
            return noise::get_dh_key_size<config.ecdh>()
                   + noise::get_kem_key_size<config.ecdh>();
        else
            static_assert(false, "The passed ECDH type is not supported.");
    }
    static constexpr std::size_t get_session_created_size() {
        if constexpr (config.ecdh == noise::ecdh_type::x25519
                      || config.ecdh == noise::ecdh_type::x448)
            return noise::get_dh_key_size<config.ecdh>() + noise_context_type::mac_size;
        else if constexpr (config.ecdh == noise::ecdh_type::x25519_hybrid_kyber1024
                           || config.ecdh == noise::ecdh_type::x448_hybrid_kyber1024)
            return noise::get_dh_key_size<config.ecdh>()
                   + noise::get_kem_cipher_text_size<config.ecdh>();
        else
            static_assert(false, "The passed ECDH type is not supported.");
    }
    static constexpr std::size_t get_session_confirmed_size() {
        return noise::get_dh_key_size<config.ecdh>() + noise_context_type::mac_size;
    }
    static constexpr std::size_t get_payload_data_size() {
        return config.payload_data_size;
    }
    static constexpr std::size_t get_payload_data_with_mac_size() {
        return config.payload_data_size + noise_context_type::mac_size;
    }
    static constexpr std::size_t get_max_payload_data_size() {
        return packet_size - sizeof(header_data_type) - noise_context_type::mac_size;
    }

public:
    static_assert(get_payload_data_with_mac_size() <= get_buffer_size(),
                  "Unexpected size of payload data.");

public:
    header_data_type header{};

    noheap::buffer_bytes_type<get_buffer_size(), noheap::rbyte> buffer{};
};

// batch
template<transport_data_config _config>
struct extention_payload_data_type {
    using transport_unit_type = transport_data_type<_config>;

public:
    noheap::buffer_type<transport_unit_type, batch_packets_count> packets;
};

template<transport_data_config config>
using transport_packet_type =
    network::packet_native_type<extention_payload_data_type<config>>;
using header_obfs_key_type = noise::buffer_type<sizeof(
    transport_packet_type<{noise::ecdh_type::x25519, 0}>::extention_data_type::
        transport_unit_type::header_data_type)>;

template<transport_data_config config>
struct transport_protocol_type
    : public network::protocol_native_type<transport_packet_type<config>,
                                           noheap::log_impl::create_owner(
                                               "ESSU_PROTOCOL")> {
    using packet_type         = transport_protocol_type<config>::packet_type;
    using transport_unit_type = packet_type::extention_data_type::transport_unit_type;

public:
    struct node_info_type {
        enum class status_type : std::size_t {
            HS1 = 0,
            HS2,
            HS3,
            CONNECTED,
        };

    public:
        node_info_type() = default;
        node_info_type(const node_info_type &node_info) { this->operator=(node_info); }
        node_info_type &operator=(const node_info_type &node_info) {
            status           = node_info.status;
            sender_ack       = node_info.sender_ack;
            receiver_ack     = node_info.receiver_ack;
            previous_packets = node_info.previous_packets;
            return *this;
        }

    public:
        status_type                        status;
        std::uint16_t                      packet_number;
        transport_unit_type::ack_data_type sender_ack;
        transport_unit_type::ack_data_type receiver_ack;

        noheap::monotonic_array<packet_type, max_node_buffered_packets> previous_packets;
    };
    using node_info_s_type =
        noheap::monotonic_array<std::pair<network::buffer_address_type, node_info_type>,
                                max_node_connection>;

public:
    constexpr void
        prepare(packet_type &pckt, network::buffer_address_type addr,
                transport_protocol_type::callback_prepare_type callback) const override {
        try {
            auto node_info_it = get_node_info_it(addr);
            if (node_info_it == node_info_s.end())
                throw noheap::runtime_error(
                    "The node connection limit has been reached.");

            callback(pckt);

            auto &node_info =
                const_cast<decltype(node_info_it->second) &>(node_info_it->second);
            pckt->packets[0].header.ack = node_info.sender_ack;
            node_info.previous_packets.push_back(pckt);

            // Calculates count of payload packets in batch
            std::size_t payload_packets_count = 0;
            for (std::size_t i = 0; i < pckt->packets.size(); ++i) {
                if (pckt->packets[i].header.flag == transport_unit_type::flag_type::drop)
                    break;
                ++payload_packets_count;
            }

            // Prepare ack-block based on receiver_ack(it was accepted)
            for (std::size_t i = pckt->packets.size();
                 i < sizeof(node_info.sender_ack.ranges) - pckt->packets.size()
                 && i / sizeof(node_info.sender_ack.ranges)
                        < node_info.packet_number - node_info.receiver_ack.ack_through;
                 i += pckt->packets.size()) {
                std::size_t it_previous_packet = node_info.packet_number
                                                 - node_info.receiver_ack.ack_through
                                                 + i / pckt->packets.size();
                if (!noheap::get_bits(node_info.receiver_ack.ranges, i,
                                      pckt->packets.size())) {
                    if (it_previous_packet >= max_node_buffered_packets)
                        throw noheap::runtime_error("The packet has been lost.");
                    pckt->packets[payload_packets_count] =
                        node_info.previous_packets[it_previous_packet]->packets[0];
                    pckt->packets[payload_packets_count + 1] =
                        node_info.previous_packets[it_previous_packet]->packets[1];
                    break;
                } else
                    node_info.previous_packets.erase(node_info.previous_packets.begin()
                                                     + it_previous_packet);
            }

            for (std::size_t i = 0; i < pckt->packets.size(); ++i) {
                auto &packet_tmp = pckt->packets[i];

                packet_tmp.header.packet_number =
                    initial_packet_number + node_info.packet_number++;

                // Adds random padding
                {
                    // Determines payload size of the packet to define size of random
                    // padding
                    std::size_t payload_data_size = packet_tmp.buffer.size();
                    if (packet_tmp.header.type
                        == transport_unit_type::payload_type::session_request)
                        payload_data_size = packet_tmp.get_session_request_size();
                    else if (packet_tmp.header.type
                             == transport_unit_type::payload_type::session_created)
                        payload_data_size = packet_tmp.get_session_created_size();
                    else if (packet_tmp.header.type
                             == transport_unit_type::payload_type::session_confirmed)
                        payload_data_size = packet_tmp.get_session_confirmed_size();
                    else if (packet_tmp.header.type
                             == transport_unit_type::payload_type::data)
                        payload_data_size = packet_tmp.get_payload_data_with_mac_size();

                    // Dummy packet
                    if (packet_tmp.header.flag == transport_unit_type::flag_type::drop)
                        payload_data_size = 0;

                    // Adds random padding after payload data
                    typename transport_unit_type::noise_context_type::cipher_state
                        cipher_state_tmp;
                    cipher_state_tmp.input_buffer.set(
                        {reinterpret_cast<noheap::rbyte *>(packet_tmp.buffer.data()),
                         packet_tmp.buffer.size()},
                        std::clamp<std::size_t>(payload_data_size, 0,
                                                packet_tmp.buffer.size()));
                    cipher_state_tmp.pad();
                }

                // Encrypts payload data and authenticates based on the header
                if (packet_tmp.header.type == transport_unit_type::payload_type::data) {
                    if (!payload_cipher_state)
                        throw noheap::runtime_error("Cipher state for payloads is null.");
                    payload_cipher_state->input_buffer.set(
                        {packet_tmp.buffer.data(),
                         packet_tmp.get_payload_data_with_mac_size()},
                        packet_tmp.get_payload_data_size());
                    payload_cipher_state->set_nonce(packet_tmp.header.packet_number);
                    payload_cipher_state->encrypt(
                        {reinterpret_cast<noheap::rbyte *>(&packet_tmp.header),
                         sizeof(packet_tmp.header)});
                }

                // Generates header obfuscation key based on the packet_number
                noise::buffer_type<sizeof(packet_tmp.header)> obfs_key_tmp{};
                crypto::chacha_encrypt(
                    {reinterpret_cast<noheap::ubyte *>(obfs_key_tmp.data()),
                     obfs_key_tmp.size()},
                    header_obfs_key, {}, packet_tmp.header.packet_number);

                // Adds header data obfuscation
                std::transform(reinterpret_cast<noheap::rbyte *>(&packet_tmp.header),
                               reinterpret_cast<noheap::rbyte *>(&packet_tmp.header)
                                   + sizeof(packet_tmp.header),
                               obfs_key_tmp.data(),
                               reinterpret_cast<noheap::rbyte *>(&packet_tmp.header),
                               std::bit_xor{});
            }

            update_protocol_status(node_info, pckt->packets[0], false);

            // Shuffle packets in batch
            std::random_device rd;
            std::mt19937       generator(rd());
            std::shuffle(pckt->packets.begin(), pckt->packets.end(), generator);

        } catch (noheap::runtime_error &excp) {
            excp.set_owner(this->buffer_owner);
            throw;
        }
    }
    constexpr void
        handle(packet_type &pckt, network::buffer_address_type addr,
               transport_protocol_type::callback_handle_type callback) const override {
        try {
            auto node_info_it = get_node_info_it(addr);
            if (node_info_it == node_info_s.end())
                return;

            auto &node_info =
                const_cast<decltype(node_info_it->second) &>(node_info_it->second);

            std::size_t payload_packet_it = 0;
            for (; payload_packet_it < pckt->packets.size(); ++payload_packet_it) {
                auto &packet_tmp = pckt->packets[payload_packet_it];

                // Selects possible packet number
                std::size_t possible_packet_number =
                    initial_packet_number + node_info.sender_ack.ack_through + 1;
                bool was_matched = false;
                for (std::size_t i = 0; i < sizeof(packet_tmp.header.packet_number) * 8;
                     ++i, ++possible_packet_number) {
                    decltype(auto) test_packet = packet_tmp;

                    // Generates header obfuscation key based on packet_number
                    noise::buffer_type<sizeof(test_packet.header)> obfs_key_tmp{};
                    crypto::chacha_encrypt(
                        {reinterpret_cast<noheap::ubyte *>(obfs_key_tmp.data()),
                         obfs_key_tmp.size()},
                        header_obfs_key, {}, possible_packet_number);

                    // Deletes header data obfuscation
                    std::transform(reinterpret_cast<noheap::rbyte *>(&test_packet.header),
                                   reinterpret_cast<noheap::rbyte *>(&test_packet.header)
                                       + sizeof(packet_tmp.header),
                                   obfs_key_tmp.data(),
                                   reinterpret_cast<noheap::rbyte *>(&test_packet.header),
                                   std::bit_xor{});
                    if (test_packet.header.packet_number == possible_packet_number) {
                        packet_tmp  = test_packet;
                        was_matched = true;
                        break;
                    }
                }

                if (!was_matched)
                    packet_tmp.header.flag = transport_unit_type::flag_type::drop;

                if (packet_tmp.header.flag == transport_unit_type::flag_type::drop)
                    continue;

                if (packet_tmp.header.type == transport_unit_type::payload_type::data) {
                    if (!payload_cipher_state)
                        throw noheap::runtime_error("Cipher state for payloads is null.");

                    // Decrypts payload data
                    payload_cipher_state->output_buffer.set(
                        {packet_tmp.buffer.data(), packet_tmp.buffer.size()},
                        packet_tmp.get_payload_data_with_mac_size());
                    payload_cipher_state->set_nonce(packet_tmp.header.packet_number);
                    payload_cipher_state->decrypt(
                        {reinterpret_cast<noheap::rbyte *>(&packet_tmp.header),
                         sizeof(packet_tmp.header)});
                }
            }

            // Restores order of packets in batch
            std::sort(pckt->packets.begin(), pckt->packets.end(),
                      [](const auto &el_left, const auto &el_right) {
                          return el_left.header.packet_number
                                 < el_right.header.packet_number;
                      });
            update_protocol_status(node_info, pckt->packets[0], true);

            // Checks own ack
            std::ssize_t ack_difference = pckt->packets[0].header.packet_number
                                          - node_info.sender_ack.ack_through
                                          - (node_info.sender_ack.ack_through ? 1 : 0);

            if (ack_difference)
                node_info.sender_ack.ranges |= noheap::get_bits(
                    std::numeric_limits<decltype(node_info.sender_ack.ranges)>::max(),
                    ack_difference, batch_packets_count);
            else
                node_info.sender_ack.ack_through =
                    pckt->packets[batch_packets_count - 1].header.packet_number;

            // Saves remote ack
            node_info.receiver_ack = pckt->packets[0].header.ack;
            if (node_info.packet_number - node_info.receiver_ack.ack_through < 0)
                node_info_s.erase(node_info_it);

            callback(std::move(pckt));
        } catch (noheap::runtime_error &excp) {
            excp.set_owner(this->buffer_owner);
            throw;
        }
    };

public:
    void set_obfs_states(typename transport_unit_type::noise_context_type::cipher_state
                                             &_payload_cipher_state,
                         header_obfs_key_type _header_obfs_key) const {
        payload_cipher_state = &_payload_cipher_state;
        std::move(_header_obfs_key.begin(), _header_obfs_key.end(),
                  header_obfs_key.begin());
    }
    void set_initial_packet_number(std::size_t _initial_packet_number) const {
        initial_packet_number = _initial_packet_number;
    }

private:
    node_info_s_type::iterator get_node_info_it(network::buffer_address_type addr) const {
        auto node_info_it = node_info_s.end();
        if (node_info_it = std::find_if(
                node_info_s.begin(), node_info_s.end(),
                [&](const auto &el) {
                    return noheap::is_equal_bytes<const noheap::ubyte>(
                        {reinterpret_cast<const noheap::ubyte *>(el.first.data()),
                         el.first.size()},
                        {reinterpret_cast<const noheap::ubyte *>(addr.data()),
                         addr.size()});
                });
            node_info_it == node_info_s.end()) {
            if (node_info_s.size() == max_node_connection)
                return node_info_it;
            const_cast<node_info_s_type &>(node_info_s)
                .push_back(typename node_info_s_type::value_type{std::move(addr),
                                                                 node_info_type{}});
        }
        return node_info_it;
    }
    void update_protocol_status(node_info_type            &node_info,
                                const transport_unit_type &packet, bool received) const {
        if (node_info.status == node_info_type::status_type::HS1
            && packet.header.type != transport_unit_type::payload_type::session_request)
            throw noheap::runtime_error("Expected session request packet.");
        else if (node_info.status == node_info_type::status_type::HS2
                     && packet.header.type
                            != transport_unit_type::payload_type::session_created
                     && !received
                 || node_info.status == node_info_type::status_type::HS2
                        && packet.header.type
                               != transport_unit_type::payload_type::session_request
                        && received)
            throw noheap::runtime_error("Expected session created packet.");
        else if (node_info.status == node_info_type::status_type::HS3
                 && packet.header.type
                        != transport_unit_type::payload_type::session_confirmed)
            throw noheap::runtime_error("Expected session confirmed packet.");
        else if (node_info.status != node_info_type::status_type::CONNECTED
                 && packet.header.flag != transport_unit_type::flag_type::wait_next)
            node_info.status = typename node_info_type::status_type(
                static_cast<std::size_t>(node_info.status) + 1);
    }

private:
    mutable typename transport_unit_type::noise_context_type::cipher_state
                                *payload_cipher_state;
    mutable header_obfs_key_type header_obfs_key;
    mutable std::uint16_t        initial_packet_number = 0;
    mutable node_info_s_type     node_info_s;
};

// Noise handshake action for establishing shared secret key
template<transport_data_config config>
struct noise_handshake_action : public network::action<transport_packet_type<config>> {
public:
    using packet_type         = noise_handshake_action::packet_type;
    using transport_unit_type = packet_type::extention_data_type::transport_unit_type;
    using noise_context_type =
        packet_type::extention_data_type::transport_unit_type::noise_context_type;
    using ephemeral_obfs_key_type = noise_context_type::dh_key_type;

    static constexpr std::size_t count_handshake_message = 3; // For XK

public:
    constexpr void init_packet(packet_type &pckt) override {
        check_noise_action(noise::noise_action::WRITE_MESSAGE);

        static typename noise_context_type::buffer_handshake_packet_type
                           noise_handshake_packet{};
        static std::size_t offset_noise_handshake_packet = 0;

        auto &payload_packet = pckt->packets[0];

        // Gets noise message
        noise_ctx.get_handshake_buffer().set(
            {noise_handshake_packet.data(), noise_handshake_packet.size()}, 0);
        noise_ctx.set_handshake_message();

        // Copy payload of the noise message
        std::copy(noise_handshake_packet.begin(),
                  noise_handshake_packet.begin() + payload_packet.buffer.size(),
                  reinterpret_cast<noheap::rbyte *>(payload_packet.buffer.begin()));

        // Fragmentation
        if (noise_ctx.get_handshake_buffer().get().size > payload_packet.buffer.size()) {
            payload_packet.header.flag = decltype(payload_packet.header.flag)::wait_next;
            offset_noise_handshake_packet += payload_packet.buffer.size();
            fragmentation = true;
        } else {
            noise_handshake_packet        = {};
            offset_noise_handshake_packet = 0;
            fragmentation                 = false;
        }

        if (noise_ctx.get_role() == noise::noise_role::INITIATOR) {
            if (number_handshake_parts == 3) {
                payload_packet.header.type =
                    transport_unit_type::payload_type::session_request;

                // Adds ephemeral key obfuscation
                std::transform(payload_packet.buffer.begin(),
                               payload_packet.buffer.begin() + ephemeral_obfs_key.size(),
                               ephemeral_obfs_key.data(), payload_packet.buffer.begin(),
                               std::bit_xor{});
            } else if (number_handshake_parts == 1)
                payload_packet.header.type =
                    transport_unit_type::payload_type::session_confirmed;
            else
                throw noheap::runtime_error("Action unreachable.");
        } else {
            if (number_handshake_parts == 2)
                payload_packet.header.type =
                    transport_unit_type::payload_type::session_created;
            else
                throw noheap::runtime_error("Action unreachable.");
        }
        --number_handshake_parts;
    }
    constexpr void process_packet(packet_type &&pckt) override {
        check_noise_action(noise::noise_action::READ_MESSAGE);

        static typename noise_context_type::buffer_handshake_packet_type
                           noise_handshake_packet{};
        static std::size_t offset_noise_handshake_packet = 0;

        auto       &payload_packet    = pckt->packets[0];
        std::size_t payload_data_size = payload_packet.buffer.size();

        // Determines size of payload data
        if (noise_ctx.get_role() == noise::noise_role::INITIATOR) {
            if (number_handshake_parts == 2)
                payload_data_size = payload_packet.get_session_created_size();
            else
                throw noheap::runtime_error("Action unreachable.");
        } else {
            if (number_handshake_parts == 3) {
                payload_data_size = payload_packet.get_session_request_size();

                // Deletes ephemeral key obfuscation
                std::transform(payload_packet.buffer.begin(),
                               payload_packet.buffer.begin() + ephemeral_obfs_key.size(),
                               ephemeral_obfs_key.begin(), payload_packet.buffer.begin(),
                               std::bit_xor{});
            } else if (number_handshake_parts == 1)
                payload_data_size = payload_packet.get_session_confirmed_size();
            else
                throw noheap::runtime_error("Action unreachable.");
        }

        // Copies accepted packet to buffer of noise handshake message
        std::copy(payload_packet.buffer.begin(), payload_packet.buffer.end(),
                  noise_handshake_packet.begin() + offset_noise_handshake_packet);
        offset_noise_handshake_packet += payload_data_size;

        // If fragmentation
        if (payload_data_size >= payload_packet.buffer.size()
            && payload_packet.header.flag == transport_unit_type::flag_type::wait_next)
            return;

        // Sets noise message
        noise_ctx.get_handshake_buffer().set(
            {noise_handshake_packet.data(), offset_noise_handshake_packet},
            payload_data_size);
        noise_ctx.get_handshake_message();
        --number_handshake_parts;
    }

public:
    noise::noise_action get_action() {
        return fragmentation ? noise::noise_action::WRITE_MESSAGE
                             : noise_ctx.get_action();
    }
    header_obfs_key_type get_header_obfs_key() { return ephemeral_header_obfs_key; }

public:
    void init(
        noise::noise_pattern pattern, noise::noise_role role,
        noise_context_type::prologue_extention_type                   &&ext,
        noise_context_type::keypair_type                              &&local_keypair,
        noise_context_type::dh_key_type                               &&remote_public_key,
        std::optional<typename noise_context_type::pre_shared_key_type> pre_shared_key) {
        // Init noise context
        noise_ctx.init(pattern, role);
        noise_ctx.set_prologue(std::move(ext));

        noise_ctx.set_local_keypair(noise_ctx.generate_keypair());
        noise_ctx.set_remote_public_key(std::move(remote_public_key));
        if (pre_shared_key.has_value())
            noise_ctx.set_pre_shared_key(std::move(*pre_shared_key));

        generate_ephemeral_obfs_key(pattern, role, local_keypair.pub, remote_public_key,
                                    pre_shared_key, ephemeral_obfs_key,
                                    ephemeral_header_obfs_key);

        noise_ctx.start();

        number_handshake_parts = count_handshake_message;
        fragmentation          = false;
    }
    noise_context_type::cipher_state dump() {
        noise_ctx.stop();
        auto cipher_state_tmp = noise_ctx.get_cipher_state();
        noise_ctx.dump();

        return cipher_state_tmp;
    }

private:
    void check_noise_action(noise::noise_action expected) {
        auto action = noise_ctx.get_action();
        if (action == noise::noise_action::FAILED)
            throw noheap::runtime_error("Failed to handshake.");

        if (action == expected)
            return;

        if (action == noise::noise_action::WRITE_MESSAGE)
            throw noheap::runtime_error("Expected message to be sent.");
        else if (action == noise::noise_action::READ_MESSAGE)
            throw noheap::runtime_error("Expected message to be received.");
        else
            throw noheap::runtime_error("Handshake already completed.");
    }
    static void generate_ephemeral_obfs_key(
        noise::noise_pattern pattern, noise::noise_role role,
        noise_context_type::dh_key_type                                &local_public_key,
        noise_context_type::dh_key_type                                &remote_public_key,
        std::optional<typename noise_context_type::pre_shared_key_type> pre_shared_key,
        ephemeral_obfs_key_type &ephemeral_obfs_key,
        header_obfs_key_type    &ephemeral_header_obfs_key) {
        typename noise_context_type::dh_key_type public_key{};
        typename noise_context_type::dh_key_type shared_key_on_time{};

        if (pattern == noise::noise_pattern::XK) {
            if (role == noise::noise_role::INITIATOR)
                public_key = remote_public_key;
            else
                public_key = local_public_key;
        }

        // Derives shared key using time stamp
        shared_key_on_time = noheap::to_buffer<decltype(public_key)>(
            std::size_t(get_now_ms() / 1000)
            + std::size_t(termination_timeout_ms / 1000));
        std::transform(public_key.begin(), public_key.end(), shared_key_on_time.begin(),
                       public_key.begin(), std::bit_xor{});

        // Generates keystream
        auto public_key_hash = typename noise_context_type::hash_state{}.get_hash(
            {public_key.data(), public_key.size()});
        noise::buffer_type<ephemeral_obfs_key_type{}.size()
                           + header_obfs_key_type{}.size()>
            keystream{};
        crypto::chacha_encrypt(
            {reinterpret_cast<noheap::ubyte *>(keystream.data()), keystream.size()},
            public_key_hash, {}, 0);

        std::copy(keystream.begin(), keystream.begin() + ephemeral_obfs_key.size(),
                  ephemeral_obfs_key.begin());
        std::copy(keystream.begin() + ephemeral_obfs_key.size(), keystream.end(),
                  ephemeral_header_obfs_key.begin());
    }

private:
    noise_context_type noise_ctx;
    std::size_t        number_handshake_parts;
    bool               fragmentation;

    ephemeral_obfs_key_type ephemeral_obfs_key;
    header_obfs_key_type    ephemeral_header_obfs_key;
};

} // namespace essu

#endif
