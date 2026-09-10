#ifndef EDDP_PROTOCOL_HPP
#define EDDP_PROTOCOL_HPP

#include "eddp_base.hpp"

namespace eddp {
struct session_info_type {
    friend class protocol;

private:
    noise_handshake_context handshake_context;

    std::uint64_t destination_id;
    std::uint32_t packet_sent_number_sender;
    std::uint32_t ack_through_sender;
    std::uint32_t ack_through_receiver;
    std::uint16_t bitmap_sender;
    std::uint16_t bitmap_receiver;

    noheap::monotonic_array<packet_type, buffer_sent_packet_size> buffer_sent_packet;
};

class protocol final {
    protocol() = delete;

public:
    static inline void prepare(session_info_type &session_info, packet_type &pckt_src,
                               essu::packet_type &pckt_dst);
    static inline void handle(session_info_type &session_info, packet_type &pckt_dst,
                              const essu::packet_type &pckt_src);
};
} // namespace eddp
void eddp::protocol::prepare(session_info_type &session_info, packet_type &pckt_src,
                             essu::packet_type &pckt_dst) {
    decltype(auto) payload_cipher_state =
        session_info.handshake_context.get_payload_cipher_state();
    decltype(auto) header_cipher_state =
        session_info.handshake_context.get_header_cipher_state_sender();
    bool session_handshake_complete = (session_info.handshake_context.get_status()
                                       == noise_handshake_context::status_enum::COMPLETE);

    // Inits packet like handshake message if necessary
    if (session_info.handshake_context.get_action()
        == noise::noise_action::WRITE_MESSAGE) {
        switch (session_info.handshake_context.get_status()) {
            case noise_handshake_context::status_enum::HS1:
                pckt_src.header.type = packet_type::packet_type_enum::session_request;
            case noise_handshake_context::status_enum::HS2:
                pckt_src.header.type = packet_type::packet_type_enum::session_created;
            case noise_handshake_context::status_enum::HS3:
                pckt_src.header.type = packet_type::packet_type_enum::session_confirmed;
            default:
                abort_invalid_state();
        }
        session_info.handshake_context.init_packet(pckt_src.buffer);
    }

    // Sets header's data
    pckt_src.header.destination_id = session_info.destination_id;
    pckt_src.header.number         = session_info.packet_sent_number_sender++;
    pckt_src.header.ack_through    = session_info.ack_through_receiver;
    pckt_src.header.bitmap         = session_info.bitmap_receiver;

    session_info.buffer_sent_packet.push_back(pckt_src);

    // Encrypts payload data
    if (session_handshake_complete) {
        payload_cipher_state.encrypt_buffer.set(pckt_src.buffer, payload_data_size);
        payload_cipher_state.encrypt({reinterpret_cast<noheap::rbyte *>(&pckt_src.header),
                                      sizeof(pckt_src.header)});
        payload_cipher_state.rekey_encrypt();
    }
    // Adds header data obfuscation except a destination_id field 
    std::transform(reinterpret_cast<noheap::rbyte *>(&pckt_src.header)
                       + sizeof(pckt_src.header.destination_id),
                   reinterpret_cast<noheap::rbyte *>(&pckt_src.header)
                       + sizeof(pckt_src.header),
                   session_info.handshake_context
                       .derive_header_obfs_key<sizeof(pckt_src.header)
                                               - sizeof(pckt_src.header.destination_id)>(
                           header_cipher_state)
                       .data(),
                   reinterpret_cast<noheap::rbyte *>(&pckt_src.header), std::bit_xor{});

    // Encapsulates eddp packet to payload of essu packet.
    pckt_dst = {};
    pckt_dst->units[0].encapsulate_buffer_data(
        noheap::to_buffer<
            const noheap::buffer_bytes_type<sizeof(pckt_src), noheap::rbyte>>(pckt_src));
    pckt_dst->units[0].set_type(essu::unit_type::unit_type_enum::data);

    for (std::size_t i = 0; i < sizeof(session_info.bitmap_sender) * 8; ++i) {
    	if(reinterpret_cast<noheap::rbyte*>(&(session_info.bitmap_sender << i)))
    }
}

#endif
