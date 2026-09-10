#ifndef EDDP_BASE_HPP
#define EDDP_BASE_HPP

#include "essu_base.hpp"
#include "mldsa_native.hpp"

// Protocol description:
// 1. Node can be firewalled and nonfirewalled; Nonfirewalled node can become a trust
// node,
//    Firewalled node can become a pseudo-trust node.
//    Trust node is provider of SFU-session or be STUN/RTUN to other nodes.
//    Pseudo-trust node is RTUN between two trust nodes.
// 2. When a node connects to trust node, the trust node have to create session or attach
// it to the existing one.
// 3. When the tust node creates session, initiator must decide a second trust node that
//    needs be a pseudo-provider - this node will just be a RTUN to provider of session.
//    Initiator must decide a packet distribution - when and which packet will be shipped.
// 4. Payload of a sent packet is encrypted for the endpoint and, in addition, is
// encrypted again between nodes.
namespace eddp {
static constexpr noise::noise_context_config<
    noise::noise_pattern::XK_HFS, noise::dh_type::X25519, noise::dh_type::MLKEM768,
    noise::cipher_type::XCHACHAPOLY, noise::hash_type::SHA3512>
    noise_config;
using noise_handshake_context = noise_handshake_context<noise_config>;

constexpr std::size_t header_data_size        = 19;
constexpr std::size_t buffer_sent_packet_size = 64;
constexpr std::size_t packet_size             = essu::payload_data_size;
constexpr std::size_t buffer_data_size        = packet_size - header_data_size;
constexpr std::size_t payload_data_size       = buffer_data_size - noise_config.mac_size;

using mldsa_wrapper = mldsa_native::mldsa_native_wrapper<std::to_array("EDDP")>;

struct [[gnu::packed]] packet_type {
    friend class protocol;

public:
    enum class packet_type_enum : std::uint8_t {
        session_request = 0,
        session_created,
        session_confirmed,
        node_resolved,
        data
    };

private:
    struct [[gnu::packed]] header_data_type {
        std::uint64_t    destination_id;
        std::uint32_t    number;
        std::uint32_t    ack_through;
        std::uint16_t    bitmap;
        packet_type_enum type;
    };
    static_assert(sizeof(header_data_type) == header_data_size, "Invalid header size.");

public:
    void             set_type(packet_type_enum type) noexcept { header.type = type; }
    packet_type_enum get_type() const noexcept { return header.type; }

private:
    header_data_type                                           header;
    noheap::buffer_bytes_type<buffer_data_size, noheap::rbyte> buffer;
};
static_assert(sizeof(packet_type) == packet_size, "Invalid packet size.");

struct [[gnu::packed]] node_info_type {
    std::uint64_t                                                id;
    noise_handshake_context::noise_context_type::buffer_key_type public_key;
    mldsa_wrapper::buffer_public_key                             sign_public_key;
};

class protocol;
struct session_info_type;

} // namespace eddp
#endif
