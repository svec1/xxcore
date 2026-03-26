#ifndef ESSU_SESSION_HPP
#define ESSU_SESSION_HPP

#include "essu_protocol.hpp"

using namespace boost;

class essu_session {
    static constexpr network::ipv         v       = network::ipv::v4;
    static constexpr noise::noise_pattern pattern = noise::noise_pattern::XK;
    static constexpr noise::ecdh_type     ecdh    = noise::ecdh_type::x25519;

    using config_type = essu::transport_data_config_type<
        pattern, ecdh, essu::decoy_transport_data_type::get_buffer_size_without_mac()>;

public:
    using wrapper_packet_type =
        network::wrapper_packet<essu::transport_packet_type<config_type>,
                                essu::transport_protocol_type<config_type>>;

public:
    using noise_handshake_action = essu::noise_handshake_action<config_type>;
    using noise_context_type     = noise_handshake_action::noise_context_type;

    using net_stream_udp = network::net_stream_udp<
        network::decoy_action<typename wrapper_packet_type::packet_type>, v>;

    using address_type = net_stream_udp::address_type;
    using port_type    = net_stream_udp::port_type;

    using buffer_session_id_type = noise::buffer_type<8>;

public:
    essu_session(address_type _remote_addr, port_type port);

public:
    // Establishes connection with node(remote_addr): performs noise handshake
    void establish_connection(
        noise::noise_role role, noise_context_type::prologue_extention_type &&ext,
        noise_context_type::keypair_type &&local_keypair,
        noise_context_type::dh_key_type  &&remote_public_key,

        typename noise_context_type::pre_shared_key_type &&pre_shared_key);

    template<network::Derived_from_action Action>
    void run_stream_session();

private:
    template<network::Net_stream_udp TStream>
    static void node_send(
        TStream &udp_stream, wrapper_packet_type &pckt,
        wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it);
    template<network::Net_stream_udp TStream>
    static void node_receive(
        TStream &udp_stream, wrapper_packet_type &pckt,
        wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it);

    static void generate_pair_ephemeral_obfs_key(
        network::buffer_address_type own_addr, network::buffer_address_type remote_addr,
        noise::noise_role role, const noise_context_type::dh_key_type &local_public_key,
        const noise_context_type::dh_key_type &remote_public_key,
        noise_context_type::dh_key_type       &ephemeral_obfs_key1,
        noise_context_type::dh_key_type       &ephemeral_obfs_key2);

    static void generate_header_obfs_key(
        const noise_context_type::hash_state::buffer_hash_type &buffer_hash,
        noise_context_type::buffer_handshake_payload_type     &&buffer_handshake_payload,
        noise_context_type::dh_key_type                        &header_obfs_key,
        buffer_session_id_type                                 &buffer_session_id);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("ESSU_SESSION");

private:
    static constexpr log_handler log{buffer_owner};

private:
    network::buffer_address_type buffer_remote_addr;
    noheap::buffer_type<char, typename network::buffer_address_v<v>::type{}.size() * 2>
                           hex_string_remote_addr;
    const std::string_view hex_remote_addr{hex_string_remote_addr.data(),
                                           hex_string_remote_addr.size()};

    net_stream_udp                   udp_stream;
    buffer_session_id_type           buffer_session_id{};
    noise_context_type::cipher_state payload_cipher_state{};
    noise_context_type::dh_key_type  header_obfs_key{};

    std::atomic<bool> running;
};

essu_session::essu_session(address_type remote_addr, port_type port)
    : buffer_remote_addr(udp_stream.get_address_bytes(remote_addr)),
      hex_string_remote_addr(
          noheap::clip_buffer<typename network::buffer_address_v<v>::type{}.size() * 2>(
              noheap::hex_encode(buffer_remote_addr))),
      udp_stream(port) {
}
void essu_session::establish_connection(
    noise::noise_role role, noise_context_type::prologue_extention_type &&ext,
    noise_context_type::keypair_type                 &&local_keypair,
    noise_context_type::dh_key_type                  &&remote_public_key,
    typename noise_context_type::pre_shared_key_type &&pre_shared_key) {
    wrapper_packet_type pckt{};
    const auto         &protocol = pckt.get_protocol();

    decltype(hex_string_remote_addr) hex_string_own_addr{};
    decltype(buffer_remote_addr)     buffer_own_addr{};

    for (auto it = pckt->packets.begin() + 1; it < pckt->packets.end(); ++it)
        it->header.flag = decltype(it->header.flag)::drop;

    auto node_it = protocol.create_node_info(buffer_remote_addr, payload_cipher_state,
                                             header_obfs_key);

    // Resolves each other's ip
    try {
        if (role == noise::noise_role::INITIATOR) {
            std::copy(reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.begin()),
                      reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.end()),
                      pckt->packets[0].buffer.begin());
            node_send(udp_stream, pckt, node_it);

            node_receive(udp_stream, pckt, node_it);
            std::copy(pckt->packets[0].buffer.begin(),
                      pckt->packets[0].buffer.begin() + buffer_own_addr.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_own_addr.begin()));
        } else {
            node_receive(udp_stream, pckt, node_it);
            std::copy(pckt->packets[0].buffer.begin(),
                      pckt->packets[0].buffer.begin() + buffer_own_addr.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_own_addr.begin()));

            std::copy(reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.begin()),
                      reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.end()),
                      pckt->packets[0].buffer.begin());
            node_send(udp_stream, pckt, node_it);
        }

        hex_string_own_addr =
            noheap::clip_buffer<typename network::buffer_address_v<v>::type{}.size() * 2>(
                noheap::hex_encode(buffer_own_addr));
    } catch (noheap::runtime_error &excp) {
        throw noheap::runtime_error(buffer_owner, "{}: Failed to resolve ip. {}",
                                    hex_remote_addr, excp.what());
    }

    protocol.set_starting_handshake(node_it);

    // Establishes connection
    try {
        network::net_stream_udp<noise_handshake_action, v> noise_udp_stream(
            udp_stream.get_port());

        // Generates ephemeral key pair to obfuscate the ephemeral key of hs1 and
        // header
        noise_context_type::dh_key_type ephemeral_obfs_key1, ephemeral_obfs_key2;
        generate_pair_ephemeral_obfs_key(buffer_own_addr, buffer_remote_addr, role,
                                         local_keypair.pub, remote_public_key,
                                         ephemeral_obfs_key1, ephemeral_obfs_key2);

        header_obfs_key = ephemeral_obfs_key1;

        // Init noise context
        auto &noise_context = noise_udp_stream.get_action();
        noise_context.init(role, std::move(ext), std::move(local_keypair),
                           std::move(remote_public_key), std::move(pre_shared_key),
                           std::move(ephemeral_obfs_key2));

        // Performs noise handshake
        while (true) {
            auto action = noise_context.get_action();
            if (action == noise::noise_action::WRITE_MESSAGE) {
                node_send(noise_udp_stream, pckt, node_it);
            } else if (action == noise::noise_action::READ_MESSAGE)
                node_receive(noise_udp_stream, pckt, node_it);
            else
                break;
        }

        // Generates header obfuscation key
        generate_header_obfs_key(noise_context.get_handshake_hash(),
                                 noise_context.get_handshake_payload(), header_obfs_key,
                                 buffer_session_id);

        payload_cipher_state = noise_context.dump();
        udp_stream           = std::move(noise_udp_stream);
    } catch (noheap::runtime_error &excp) {
        throw noheap::runtime_error(buffer_owner,
                                    "{}: Failed to establish connection. {}",
                                    hex_remote_addr, excp.what());
    }

    log.to_all("Connection has been established: {}",
               std::string_view(noheap::hex_encode(buffer_session_id)));
}
template<network::Derived_from_action Action>
void essu_session::run_stream_session() {
    network::net_stream_udp<Action, v> session_udp_stream(udp_stream.get_port());
    session_udp_stream = std::move(udp_stream);

    const auto &protocol = wrapper_packet_type::get_protocol();
    const auto  node_it  = protocol.get_node_info(buffer_remote_addr);

    running.store(true);

    future_wrapper future_object_to_send([&]() {
        try {
            wrapper_packet_type pckt{};

            while (running.load())
                node_send(session_udp_stream, pckt, node_it);
        } catch (...) {
            running.store(false);
            throw;
        }
    });
    future_wrapper future_object_to_receive([&]() {
        try {
            wrapper_packet_type pckt{};

            while (running.load())
                node_receive(session_udp_stream, pckt, node_it);
        } catch (...) {
            running.store(false);
            throw;
        }
    });

    try {
        future_object_to_send.get();
        future_object_to_receive.get();
    } catch (noheap::runtime_error &excp) {
        throw noheap::runtime_error(buffer_owner, "{}: Connection terminated. {}",
                                    hex_remote_addr, excp.what());
    }
}

template<network::Net_stream_udp TStream>
void essu_session::node_send(
    TStream &udp_stream, wrapper_packet_type &pckt,
    wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it) {
    udp_stream.template send_to<decltype(pckt)>(
        pckt, TStream::get_address_object(node_it->first));
}
template<network::Net_stream_udp TStream>
void essu_session::node_receive(
    TStream &udp_stream, wrapper_packet_type &pckt,
    wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it) {
    future_wrapper f([&]() {
        udp_stream.template async_receive_from<decltype(pckt)>(
            pckt, TStream::get_address_object(node_it->first));
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
        noheap::clip_buffer<32>(typename noise_context_type::hash_state{}.get_hash(
            {public_key.data(), public_key.size()}));

    // Generates keystream
    noise::buffer_type<typename noise_context_type::dh_key_type{}.size() * 2> keystream{};
    crypto::chacha_encrypt(
        {reinterpret_cast<noheap::ubyte *>(keystream.data()), keystream.size()},
        noheap::to_buffer<const crypto::buffer_key_type &>(public_key_hash), {}, 0);

    std::copy(keystream.begin(),
              keystream.begin() + noise_context_type::dh_key_type{}.size(),
              ephemeral_obfs_key1.begin());
    std::copy(keystream.begin() + noise_context_type::dh_key_type{}.size(),
              keystream.end(), ephemeral_obfs_key2.begin());
}
void essu_session::generate_header_obfs_key(
    const noise_context_type::hash_state::buffer_hash_type &buffer_hash,
    noise_context_type::buffer_handshake_payload_type     &&buffer_handshake_payload,
    noise_context_type::dh_key_type                        &header_obfs_key,
    buffer_session_id_type                                 &buffer_session_id) {
    // Generates hash from previous result
    std::decay_t<decltype(buffer_hash)> output1, output2;
    typename noise_context_type::hash_state{}.hkdf(
        {buffer_hash.data(), buffer_hash.size()},
        {buffer_handshake_payload.data(), buffer_handshake_payload.size()},
        {output1.data(), output1.size()}, {output2.data(), output2.size()});

    // Generates keystream
    noise::buffer_type<noise_context_type::dh_key_type{}.size()> keystream{};
    crypto::chacha_encrypt(
        {reinterpret_cast<noheap::ubyte *>(keystream.data()), keystream.size()},
        noheap::to_buffer<const crypto::buffer_key_type &>(output1), {}, 0);

    std::copy(keystream.begin(), keystream.end(), header_obfs_key.begin());
    std::copy(output2.begin(), output2.begin() + buffer_session_id.size(),
              buffer_session_id.begin());
}

#endif
