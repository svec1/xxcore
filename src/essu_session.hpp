#ifndef ESSU_SESSION_HPP
#define ESSU_SESSION_HPP

#include "essu_protocol.hpp"

using namespace boost;

class essu_session {
    static constexpr network::ipv         v       = network::ipv::v4;
    static constexpr noise::noise_pattern pattern = noise::noise_pattern::XK;
    static constexpr noise::ecdh_type     ecdh    = noise::ecdh_type::x25519;

    using config_type       = essu::unit_config_type<pattern, ecdh, 280>;
    using session_info_type = essu::session_info_type<config_type>;

public:
    using wrapper_packet_type =
        network::wrapper_packet<essu::packet_type<config_type>,
                                essu::protocol_type<session_info_type>>;

public:
    using noise_handshake_action = essu::noise_handshake_action<config_type>;
    using noise_context_type     = noise_handshake_action::noise_context_type;

    using net_stream_udp = network::net_stream_udp<
        network::decoy_action<typename wrapper_packet_type::packet_type>, v>;

    using address_type = net_stream_udp::address_type;
    using port_type    = net_stream_udp::port_type;

    using buffer_unique_value_type = noise::buffer_type<32>;

public:
    essu_session(address_type _remote_addr, port_type port);

public:
    // Establishes connection with node(remote_addr): performs noise handshake
    void establish_connection(
        noise::noise_role role, noise_context_type::prologue_extention_type ext,
        const noise_context_type::keypair_type        &local_keypair,
        const noise_context_type::dh_key_type         &remote_public_key,
        const noise_context_type::pre_shared_key_type &pre_shared_key);

    template<network::Derived_from_action Action>
    void run_stream_session();

private:
    template<typename... Args>
    void message(std::format_string<Args...> format, Args &&...args);
    template<typename... Args>
    void throw_error(std::format_string<Args...> format, Args &&...args);

private:
    template<network::Net_stream_udp TStream>
    static void node_send(TStream &udp_stream, wrapper_packet_type &pckt,
                          const session_info_type &session_info);
    template<network::Net_stream_udp TStream>
    static void node_receive(TStream &udp_stream, wrapper_packet_type &pckt,
                             const session_info_type &session_info);

    static void generate_pair_ephemeral_obfs_key(
        network::buffer_address_type own_addr, network::buffer_address_type remote_addr,
        noise::noise_role role, const noise_context_type::dh_key_type &local_public_key,
        const noise_context_type::dh_key_type &remote_public_key,
        noise_context_type::dh_key_type       &ephemeral_obfs_key1,
        noise_context_type::dh_key_type       &ephemeral_obfs_key2);

    static void generate_pair_session_unique_value(
        const noise_context_type::hash_state::buffer_type       &buffer_handshake_hash,
        const noise_context_type::buffer_handshake_payload_type &buffer_handshake_payload,
        buffer_unique_value_type &output_value1, buffer_unique_value_type &output_value2);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("ESSU_SESSION");

private:
    static constexpr log_handler log{buffer_owner};

private:
    session_info_type info;
    net_stream_udp    udp_stream;
    std::size_t       session_id;

    noheap::buffer_chars_type<noheap::buffer_size<network::buffer_address_v<v>::type> * 2>
                           buffer_hex_remote_addr;
    const std::string_view hex_remote_addr{buffer_hex_remote_addr};

    std::atomic<bool> running;
};

essu_session::essu_session(address_type remote_addr, port_type port)
    : info(udp_stream.get_address_bytes(remote_addr)),
      buffer_hex_remote_addr(
          noheap::clip_buffer<noheap::buffer_size<decltype(buffer_hex_remote_addr)>, 0>(
              noheap::hex_encode(info.addr))),
      udp_stream(port) {
}
void essu_session::establish_connection(
    noise::noise_role role, noise_context_type::prologue_extention_type ext,
    const noise_context_type::keypair_type        &local_keypair,
    const noise_context_type::dh_key_type         &remote_public_key,
    const noise_context_type::pre_shared_key_type &pre_shared_key) {
    wrapper_packet_type pckt{};
    const auto         &protocol = pckt.get_protocol();

    network::buffer_address_type     buffer_own_addr;
    decltype(buffer_hex_remote_addr) buffer_hex_own_addr;

    for (auto it = pckt->units.begin() + 1; it < pckt->units.end(); ++it)
        it->header.flag = decltype(it->header.flag)::drop;

    protocol.register_session_info(info);

    this->message("Creating essu session...");
    this->message("Remote public key: {}",
                  std::string_view(noheap::hex_encode(remote_public_key)));

    // Resolves each other's ip
    try {
        if (role == noise::noise_role::INITIATOR) {
            std::copy(reinterpret_cast<const noheap::rbyte *>(info.addr.begin()),
                      reinterpret_cast<const noheap::rbyte *>(info.addr.end()),
                      pckt->units[0].buffer.begin());
            node_send(udp_stream, pckt, info);

            node_receive(udp_stream, pckt, info);
            std::copy(pckt->units[0].buffer.begin(),
                      pckt->units[0].buffer.begin() + buffer_own_addr.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_own_addr.begin()));
        } else {
            node_receive(udp_stream, pckt, info);
            std::copy(pckt->units[0].buffer.begin(),
                      pckt->units[0].buffer.begin() + buffer_own_addr.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_own_addr.begin()));

            std::copy(reinterpret_cast<const noheap::rbyte *>(info.addr.begin()),
                      reinterpret_cast<const noheap::rbyte *>(info.addr.end()),
                      pckt->units[0].buffer.begin());
            node_send(udp_stream, pckt, info);
        }

        buffer_hex_own_addr =
            noheap::clip_buffer<noheap::buffer_size<decltype(buffer_hex_own_addr)>, 0>(
                noheap::hex_encode(buffer_own_addr));
    } catch (noheap::runtime_error &excp) {
        this->throw_error("Failed to resolve ip. {}", excp.what());
    }

    protocol.set_starting_handshake(info);

    // Establishes connection
    try {
        network::net_stream_udp<noise_handshake_action, v> noise_udp_stream(
            udp_stream.get_port());

        // Generates ephemeral key pair to obfuscate the ephemeral key of hs1 and
        // header
        noise_context_type::dh_key_type ephemeral_obfs_key1, ephemeral_obfs_key2;
        generate_pair_ephemeral_obfs_key(buffer_own_addr, info.addr, role,
                                         local_keypair.pub, remote_public_key,
                                         ephemeral_obfs_key1, ephemeral_obfs_key2);

        info.header_cipher_state.set_key(ephemeral_obfs_key1);

        // Init noise context
        auto &noise_context = noise_udp_stream.get_action();
        noise_context.init(role, std::move(ext), std::move(local_keypair),
                           std::move(remote_public_key), std::move(pre_shared_key),
                           std::move(ephemeral_obfs_key2));

        // Performs noise handshake
        while (true) {
            auto action = noise_context.get_action();
            if (action == noise::noise_action::WRITE_MESSAGE) {
                node_send(noise_udp_stream, pckt, info);
            } else if (action == noise::noise_action::READ_MESSAGE) {
                node_receive(noise_udp_stream, pckt, info);
            } else
                break;
        }

        // Gets finally cipher state
        info.payload_cipher_state = noise_context.dump();
        udp_stream                = std::move(noise_udp_stream);

        // Generates values for header obfs key + initial packet number + session_id
        buffer_unique_value_type value1{}, value2{};
        generate_pair_session_unique_value(noise_context.get_handshake_hash(),
                                           noise_context.get_handshake_payload(), value1,
                                           value2);

        info.header_cipher_state.set_key(value1);
        session_id = noheap::represent_bytes<std::size_t>(
            noheap::clip_buffer<sizeof(std::size_t), 0>(value2));

        const std::uint32_t subvalue1 = noheap::represent_bytes<std::uint32_t>(
            noheap::clip_buffer<sizeof(std::uint32_t), sizeof(std::size_t)>(value2));
        const std::uint32_t subvalue2 = noheap::represent_bytes<std::uint32_t>(
            noheap::clip_buffer<sizeof(std::uint32_t),
                                sizeof(std::size_t) + sizeof(std::uint32_t)>(value2));

        if (role == noise::noise_role::INITIATOR)
            protocol.set_initial_unit_number(info, subvalue1, subvalue2);
        else
            protocol.set_initial_unit_number(info, subvalue2, subvalue1);
    } catch (noheap::runtime_error &excp) {
        this->throw_error("Failed to establish connection. {}", excp.what());
    }

    this->message("{} session is established.", session_id);
}
template<network::Derived_from_action Action>
void essu_session::run_stream_session() {
    network::net_stream_udp<Action, v> session_udp_stream(udp_stream.get_port());
    session_udp_stream = std::move(udp_stream);

    const auto &protocol = wrapper_packet_type::get_protocol();

    running.store(true);

    future_wrapper future_object_to_send([&]() {
        try {
            wrapper_packet_type pckt{};

            while (running.load())
                node_send(session_udp_stream, pckt, info);
        } catch (...) {
            running.store(false);
            throw;
        }
    });
    future_wrapper future_object_to_receive([&]() {
        try {
            wrapper_packet_type pckt{};

            while (running.load())
                node_receive(session_udp_stream, pckt, info);
        } catch (...) {
            running.store(false);
            throw;
        }
    });

    try {
        future_object_to_send.get();
        future_object_to_receive.get();
    } catch (noheap::runtime_error &excp) {
        this->throw_error("Connection terminated. {}", excp.what());
    }
}

template<typename... Args>
void essu_session::message(std::format_string<Args...> format, Args &&...args) {
    noheap::buffer_chars_type<noheap::print_impl::buffer_size
                              - noheap::buffer_size<decltype(buffer_owner)>
                              - noheap::buffer_size<decltype(buffer_hex_remote_addr)>>
        buffer_format{};
    std::format_to_n(buffer_format.begin(), buffer_format.size(), format,
                     std::forward<Args>(args)...);
    log.to_all("{}: {}", hex_remote_addr, std::string_view(buffer_format));
}
template<typename... Args>
void essu_session::throw_error(std::format_string<Args...> format, Args &&...args) {
    noheap::buffer_chars_type<noheap::runtime_error::buffer_size
                              - noheap::buffer_size<decltype(buffer_owner)>
                              - noheap::buffer_size<decltype(buffer_hex_remote_addr)>>
        buffer_format{};
    std::format_to_n(buffer_format.begin(), buffer_format.size(), format,
                     std::forward<Args>(args)...);
    throw noheap::runtime_error(buffer_owner, "{}: {}", hex_remote_addr,
                                std::string_view(buffer_format));
}

template<network::Net_stream_udp TStream>
void essu_session::node_send(TStream &udp_stream, wrapper_packet_type &pckt,
                             const session_info_type &session_info) {
    udp_stream.template send_to<decltype(pckt)>(
        pckt, TStream::get_address_object(session_info.addr));
}
template<network::Net_stream_udp TStream>
void essu_session::node_receive(TStream &udp_stream, wrapper_packet_type &pckt,
                                const session_info_type &session_info) {
    future_wrapper f([&]() {
        udp_stream.template async_receive_from<decltype(pckt)>(
            pckt, TStream::get_address_object(session_info.addr));
        udp_stream.run();
    });

    // Waits to receive packet
    if (!f.is_completed(wrapper_packet_type::protocol_type::timeout_ms)) {
        udp_stream.cancel();
        throw noheap::runtime_error("Timeout has been reached.");
    }

    f.get();
}

void essu_session::generate_pair_ephemeral_obfs_key(
    network::buffer_address_type own_addr, network::buffer_address_type remote_addr,
    noise::noise_role role, const noise_context_type::dh_key_type &local_public_key,
    const noise_context_type::dh_key_type &remote_public_key,
    noise_context_type::dh_key_type       &ephemeral_obfs_key1,
    noise_context_type::dh_key_type       &ephemeral_obfs_key2) {
    typename noise_context_type::dh_key_type public_key{};
    const auto xor_public_key_with_addr = [&](const auto &addr) {
        std::transform(public_key.begin(), public_key.begin() + addr.size(),
                       reinterpret_cast<const noheap::rbyte *>(addr.begin()),
                       public_key.begin(), std::bit_xor{});
    };

    if (role == noise::noise_role::INITIATOR)
        public_key = remote_public_key;
    else
        public_key = local_public_key;

    // Derives shared key using own and remote addresses
    xor_public_key_with_addr(own_addr);
    xor_public_key_with_addr(remote_addr);

    // Gets 32 bytes-hash of public key
    auto public_key_hash =
        noheap::clip_buffer<32, 0>(typename noise_context_type::hash_state{}.get_hash(
            {public_key.data(), public_key.size()}));

    // Generates keystream
    noise::buffer_type<noheap::buffer_size<noise_context_type::dh_key_type> * 2
                       + noise_context_type::mac_size>
                                     keystream{};
    noise_context_type::cipher_state cipher_tmp;
    cipher_tmp.set_key(public_key_hash);
    cipher_tmp.input_buffer.set({keystream.data(), keystream.size()},
                                keystream.size() - noise_context_type::mac_size);
    cipher_tmp.encrypt({});

    std::copy(keystream.begin(),
              keystream.begin() + noise_context_type::dh_key_type{}.size(),
              ephemeral_obfs_key1.begin());
    std::copy(keystream.begin() + noise_context_type::dh_key_type{}.size(),
              keystream.end(), ephemeral_obfs_key2.begin());
}
void essu_session::generate_pair_session_unique_value(
    const noise_context_type::hash_state::buffer_type       &buffer_handshake_hash,
    const noise_context_type::buffer_handshake_payload_type &buffer_handshake_payload,
    buffer_unique_value_type &output_value1, buffer_unique_value_type &output_value2) {
    // Generates unique values
    std::decay_t<decltype(buffer_handshake_hash)> output_tmp1;
    typename noise_context_type::hash_state{}.hkdf(
        {buffer_handshake_hash.data(), buffer_handshake_hash.size()},
        {buffer_handshake_payload.data(), buffer_handshake_payload.size()},
        {output_tmp1.data(), output_tmp1.size()},
        {output_value2.data(), output_value2.size()});

    // Generates keystream - the first output value
    noise::buffer_type<noheap::buffer_size<buffer_unique_value_type>
                       + noise_context_type::mac_size>
                                     keystream{};
    noise_context_type::cipher_state cipher_tmp;
    cipher_tmp.set_key(noheap::clip_buffer<32, 0>(output_tmp1));
    cipher_tmp.input_buffer.set({keystream.data(), keystream.size()},
                                keystream.size() - noise_context_type::mac_size);
    cipher_tmp.encrypt({});

    std::copy(keystream.begin(),
              keystream.begin() + noheap::buffer_size<buffer_unique_value_type>,
              output_value1.begin());
}

#endif
