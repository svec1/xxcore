#ifndef ESSU_SESSION_HPP
#define ESSU_SESSION_HPP

#include "essu_protocol.hpp"

using namespace boost;

template<network::ipv v, network::Packet TPacket, network::Derived_from_action Action>
class essu_session {
    using net_stream_decoy =
        network::net_stream_udp<network::decoy_action<network::packet_native_type<char>>,
                                v>;
    using address_type = net_stream_decoy::address_type;
    using port_type    = net_stream_decoy::port_type;
    using packet_type  = TPacket;

    static constexpr essu::transport_data_config packet_config =
        packet_type::packet_type::extention_data_type::transport_unit_type::get_config();

public:
    using noise_handshake_action = essu::noise_handshake_action<{
        packet_config.ecdh, packet_type::packet_type::extention_data_type::
                                transport_unit_type::get_max_payload_data_size()}>;
    using noise_packet_type =
        network::packet<typename noise_handshake_action::packet_type,
                        essu::transport_protocol_type<
                            noise_handshake_action::packet_type::extention_data_type::
                                transport_unit_type::get_config()>>;
    using noise_context_type = noise_handshake_action::noise_context_type;

public:
    essu_session(address_type _addr, port_type port);

public:
    void establish_connection(
        noise::noise_pattern pattern, noise::noise_role role,
        noise_context_type::prologue_extention_type                   &&ext,
        noise_context_type::keypair_type                              &&local_keypair,
        noise_context_type::dh_key_type                               &&remote_public_key,
        std::optional<typename noise_context_type::pre_shared_key_type> pre_shared_key);

    void run_stream_session();

private:
    asio::io_context io;
    address_type     addr;

    network::net_stream_udp<Action, v> udp_stream;
    noise_context_type::cipher_state   payload_cipher_state;
};

template<network::ipv v, network::Packet TPacket, network::Derived_from_action Action>
essu_session<v, TPacket, Action>::essu_session(address_type _addr, port_type port)
    : addr(_addr), udp_stream(io, port) {
}
template<network::ipv v, network::Packet TPacket, network::Derived_from_action Action>
void essu_session<v, TPacket, Action>::establish_connection(
    noise::noise_pattern pattern, noise::noise_role role,
    noise_context_type::prologue_extention_type                   &&ext,
    noise_context_type::keypair_type                              &&local_keypair,
    noise_context_type::dh_key_type                               &&remote_public_key,
    std::optional<typename noise_context_type::pre_shared_key_type> pre_shared_key) {
    network::net_stream_udp<noise_handshake_action, v> noise_udp_stream(
        io, udp_stream.get_port());
    noise_packet_type pckt{};

    auto &noise_context = noise_udp_stream.get_action();
    noise_context.init(pattern, role, std::move(ext), std::move(local_keypair),
                       std::move(remote_public_key), pre_shared_key);

    const auto &protocol = pckt.get_protocol();
    protocol.set_obfs_states(payload_cipher_state, noise_context.get_header_obfs_key(),
                             0);

    auto buffer_addr = noise_udp_stream.get_address_bytes(addr);

    while (true) {
        auto action = noise_context.get_action();
        if (action == noise::noise_action::WRITE_MESSAGE)
            noise_udp_stream.template send_to<decltype(pckt)>(pckt, addr);
        else if (action == noise::noise_action::READ_MESSAGE) {
            future_wrapper f([&]() {
                noise_udp_stream.template async_receive_from<decltype(pckt)>(pckt);
                noise_udp_stream.io_context_run();
            });

            // Waits to receive packet
            if (!f.is_completed(essu::termination_timeout_ms)) {
                auto buffer_tmp = noheap::to_hex_string(buffer_addr);
                throw noheap::runtime_error(
                    "Timeout has been reached: {}",
                    std::string_view(buffer_tmp.data(), buffer_tmp.size()));
            }

            f.get();

        } else
            break;
    }
    payload_cipher_state = noise_context.dump();

    udp_stream = std::move(noise_udp_stream);
}
template<network::ipv v, network::Packet TPacket, network::Derived_from_action Action>
void essu_session<v, TPacket, Action>::run_stream_session() {
    std::future<void> payload_handler = std::async(std::launch::async, [&] {
        packet_type pckt_for_receiving{}, pckt_for_sending{};

        udp_stream.template register_send_handler<0>(pckt_for_sending, addr);
        udp_stream.register_receive_handler(pckt_for_receiving);

        udp_stream.io_context_run();
    });
}

#endif
