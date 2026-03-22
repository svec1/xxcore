#ifndef ESSU_SESSION_HPP
#define ESSU_SESSION_HPP

#include "essu_protocol.hpp"

using namespace boost;

template<network::ipv v, network::Wrapper_packet TPacket,
         network::Derived_from_action Action>
class essu_session {
    using wrapper_packet_type = TPacket;

    static constexpr essu::transport_data_config packet_config = wrapper_packet_type::
        packet_type::extention_data_type::transport_unit_type::get_config();

public:
    using noise_handshake_action = essu::noise_handshake_action<packet_config>;
    using noise_context_type     = noise_handshake_action::noise_context_type;
    using net_stream_decoy       = network::net_stream_udp<
        network::decoy_action<typename noise_handshake_action::packet_type>, v>;

    using address_type = net_stream_decoy::address_type;
    using port_type    = net_stream_decoy::port_type;

public:
    essu_session(address_type _remote_addr, port_type port);

public:
    // Establishes connection with node(remote_addr): performs noise handshake
    void establish_connection(
        noise::noise_pattern pattern, noise::noise_role role,
        noise_context_type::prologue_extention_type                   &&ext,
        noise_context_type::keypair_type                              &&local_keypair,
        noise_context_type::dh_key_type                               &&remote_public_key,
        std::optional<typename noise_context_type::pre_shared_key_type> pre_shared_key);

    void run_stream_session();

private:
    template<network::Net_stream_udp TStream>
    static void send(
        TStream &udp_stream, wrapper_packet_type &pckt,
        wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it);
    template<network::Net_stream_udp TStream>
    static void receive(
        TStream &udp_stream, wrapper_packet_type &pckt,
        wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("ESSU_SESSION");

private:
    static constexpr log_handler log{buffer_owner};

private:
    address_type remote_addr;

    network::net_stream_udp<Action, v> udp_stream;
    noise_context_type::cipher_state   payload_cipher_state{};
    noise_context_type::dh_key_type    header_obfs_key{};
};

template<network::ipv v, network::Wrapper_packet TWrapper_Packet,
         network::Derived_from_action Action>
essu_session<v, TWrapper_Packet, Action>::essu_session(address_type _remote_addr,
                                                       port_type    port)
    : remote_addr(_remote_addr), udp_stream(port) {
}
template<network::ipv v, network::Wrapper_packet TWrapper_Packet,
         network::Derived_from_action Action>
void essu_session<v, TWrapper_Packet, Action>::establish_connection(
    noise::noise_pattern pattern, noise::noise_role role,
    noise_context_type::prologue_extention_type                   &&ext,
    noise_context_type::keypair_type                              &&local_keypair,
    noise_context_type::dh_key_type                               &&remote_public_key,
    std::optional<typename noise_context_type::pre_shared_key_type> pre_shared_key) {
    wrapper_packet_type pckt{};
    const auto         &protocol = pckt.get_protocol();

    auto buffer_remote_addr     = udp_stream.get_address_bytes(remote_addr);
    auto hex_string_remote_addr = noheap::to_hex_string(buffer_remote_addr);
    decltype(buffer_remote_addr) buffer_own_addr{};

    for (auto it = pckt->packets.begin() + 1; it < pckt->packets.end(); ++it)
        it->header.flag = decltype(it->header.flag)::drop;

    auto node_it = protocol.create_node_info(buffer_remote_addr, payload_cipher_state,
                                             header_obfs_key);

    // Resolves each other's ip
    try {
        net_stream_decoy resolves_ip_udp_stream(udp_stream.get_port());
        if (role == noise::noise_role::INITIATOR) {
            std::copy(reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.begin()),
                      reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.end()),
                      pckt->packets[0].buffer.begin());
            send(resolves_ip_udp_stream, pckt, node_it);

            receive(resolves_ip_udp_stream, pckt, node_it);
            std::copy(pckt->packets[0].buffer.begin(),
                      pckt->packets[0].buffer.begin() + buffer_own_addr.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_own_addr.begin()));
        } else {
            receive(resolves_ip_udp_stream, pckt, node_it);
            std::copy(pckt->packets[0].buffer.begin(),
                      pckt->packets[0].buffer.begin() + buffer_own_addr.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_own_addr.begin()));

            std::copy(reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.begin()),
                      reinterpret_cast<noheap::rbyte *>(buffer_remote_addr.end()),
                      pckt->packets[0].buffer.begin());
            send(resolves_ip_udp_stream, pckt, node_it);
        }
    } catch (noheap::runtime_error &excp) {
        throw noheap::runtime_error(buffer_owner, "{}: Failed to resolve ip. {}",
                                    std::string_view(hex_string_remote_addr.data(),
                                                     hex_string_remote_addr.size()),
                                    excp.what());
    }

    protocol.set_starting_handshake(node_it);

    // Establishes connection
    try {
        network::net_stream_udp<noise_handshake_action, v> noise_udp_stream(
            udp_stream.get_port());

        // Init noise context
        auto &noise_context = noise_udp_stream.get_action();
        noise_context.init(buffer_own_addr, buffer_remote_addr, pattern, role,
                           std::move(ext), std::move(local_keypair),
                           std::move(remote_public_key), pre_shared_key);
        header_obfs_key = noise_context.get_header_obfs_key();

        // Performs noise handshake
        while (true) {
            auto action = noise_context.get_action();
            if (action == noise::noise_action::WRITE_MESSAGE) {
                send(noise_udp_stream, pckt, node_it);
            } else if (action == noise::noise_action::READ_MESSAGE)
                receive(noise_udp_stream, pckt, node_it);
            else
                break;
        }

        payload_cipher_state = noise_context.dump();
        udp_stream           = std::move(noise_udp_stream);
    } catch (noheap::runtime_error &excp) {
        throw noheap::runtime_error(buffer_owner,
                                    "{}: Failed to establish connection. {}",
                                    std::string_view(hex_string_remote_addr.data(),
                                                     hex_string_remote_addr.size()),
                                    excp.what());
    }
}
template<network::ipv v, network::Wrapper_packet TWrapper_packet,
         network::Derived_from_action Action>
void essu_session<v, TWrapper_packet, Action>::run_stream_session() {
    // TODO
    std::future<void> payload_handler = std::async(std::launch::async, [&] {
        wrapper_packet_type pckt_for_receiving{}, pckt_for_sending{};

        udp_stream.io_context_run();
    });
}
template<network::ipv v, network::Wrapper_packet TWrapper_packet,
         network::Derived_from_action Action>
template<network::Net_stream_udp TStream>
void essu_session<v, TWrapper_packet, Action>::send(
    TStream &udp_stream, wrapper_packet_type &pckt,
    wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it) {
    udp_stream.template send_to<decltype(pckt)>(
        pckt, TStream::get_address_object(node_it->first));
}
template<network::ipv v, network::Wrapper_packet TWrapper_packet,
         network::Derived_from_action Action>
template<network::Net_stream_udp TStream>
void essu_session<v, TWrapper_packet, Action>::receive(
    TStream &udp_stream, wrapper_packet_type &pckt,
    wrapper_packet_type::protocol_type::node_info_s_type::const_iterator node_it) {
    while (!pckt.get_protocol().was_accepted(node_it)) {
        future_wrapper f([&]() {
            udp_stream.template async_receive_from<decltype(pckt)>(
                pckt, TStream::get_address_object(node_it->first));
            udp_stream.io_context_run();
        });

        // Waits to receive packet
        if (!f.is_completed(essu::termination_timeout_ms)
            || pckt.get_protocol().timeout_reached(node_it)) {
            udp_stream.socket_cancel();
            throw noheap::runtime_error(buffer_owner, "Timeout has been reached.");
        }

        f.get();
    }
}

#endif
