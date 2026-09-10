#ifndef ESSU_BASE_HPP
#define ESSU_BASE_HPP

#include "network.hpp"
#include "noise_handshake_context.hpp"
#include "utils.hpp"

// Protocol description:
// ESSU-Protocol is encrypted deterministic-size uncorrelated semi-asynchronous
// not-reliable UDP protocol.
// 1. Each packet contains batch_units_number units:
// 	- 1,2 might contain payload data
// 	- 3 is control unit which contain a control notification in the header field and
// random padding.
// 	- 4 is dummy unit which contain only random padding.
//    NOTE: these units will be mixed together before the sending and restored in order
//    after the receiving.
// 2. Establishing connection between two nodes have to establish handshake
// NoisePSK_XXhfs_25519+MLKEM768_XChaChaPoly_SHA3512.
//    The starting of the handshake is the sending a session_request packet.
//    The result of the handshake is the sending a session_confirmed packet and derived:
//    	- a header_cipher_state for encrypt header data of unit.
//    	- a payload_cipher_state for encrypt payload data of unit.
//      - a handshake_payload for double ratchet.
//      - a handshake_id for IP rotation, which changes from handshake to handshake.
//    The handshake_payload is a payload data of session_confirmed packet. It will be
//    updated from handshake to handshake - will derive from new and old version. The
//    handshake packet will be sent with a [sent_handshake_batch_factor]% factor NOTE:
//    When node 1(initiator) sent session_confirmed packet, node 2 still might send
//    packets used a prehandshake header_cipher_state for some time. 	    Then node 1
//    will has to skip those packets(max count is skip_batch_window_number) until it
//    decrypts at least one.
// 3. After establishing connection, both nodes will have to fulfill conditions:
//    	- Rekey of payload_cipher_state every unit_per_rekey_number packets.
//    	- One of the node that reached max_available_batch_number for batch_sent_number
//    has to send a packet with retry control unit.
//      - This node will have to continue send new packets until receiver sends the same
//      packet
//        after that receiver needs to skip packets until it receives a session_request
//        packet to establish handshake again.
// NOTE: Max count of available handshake is max_available_handshake_number.
namespace essu {
static constexpr noise::noise_context_config<
    noise::noise_pattern::XX_HFS, noise::dh_type::X25519, noise::dh_type::MLKEM768,
    noise::cipher_type::XCHACHAPOLY, noise::hash_type::SHA3512>
    noise_config;

using noise_handshake_context = noise_handshake_context<noise_config>;

constexpr std::size_t timeout_ms                 = 7500;
constexpr std::size_t packet_size                = 1376;
constexpr std::size_t header_data_size           = 17;
constexpr std::size_t batch_units_number         = 4;
constexpr std::size_t control_unit_number        = 3;
constexpr std::size_t unit_per_rekey_number      = 6;
constexpr std::size_t batch_window_number        = 256;
constexpr std::size_t skip_batch_window_number   = 80;
constexpr std::size_t max_batch_handshake_number = 48;
constexpr std::size_t min_available_batch_number = 10240;
constexpr std::size_t max_available_batch_number =
    (std::uint32_t(-1) - skip_batch_window_number) / batch_units_number;
constexpr std::size_t max_available_handshake_number = std::uint16_t(-1);
constexpr std::size_t max_session_number             = 4;
constexpr std::size_t sent_handshake_batch_factor    = 50;
constexpr std::size_t unit_size                      = packet_size / batch_units_number;
constexpr std::size_t buffer_data_size               = unit_size - header_data_size;
constexpr std::size_t payload_data_size = buffer_data_size - noise_config.mac_size;

// Transport unit
struct [[gnu::packed]] unit_type {
    friend class protocol;
    friend struct extention_payload_data_type;

public:
    enum class unit_type_enum : std::uint8_t {
        dummy = 0,
        session_request,
        session_created,
        session_confirmed,
        session_retry,
        hole_punch,
        data,
    };

private:
    struct [[gnu::packed]] header_data_type {
        std::uint64_t  connection_id;
        std::uint32_t  number;
        std::uint32_t  key_iteration_number;
        unit_type_enum type;
    };
    static_assert(sizeof(header_data_type) == header_data_size, "Invalid header size.");

public:
    template<noheap::Buffer_bytes T>
        requires(noheap::buffer_size<T> <= buffer_data_size)
    void encapsulate_buffer_data(T &&_buffer) {
        std::memcpy(buffer.data(), &_buffer, _buffer.size());
    }
    template<noheap::Buffer_bytes T>
        requires(noheap::buffer_size<T> <= buffer_data_size)
    T decapsulate_buffer_data() {
        T _buffer;
        std::memcpy(&_buffer, buffer.data(), _buffer.size());
        return _buffer;
    }

    void           set_type(unit_type_enum type) noexcept { header.type = type; }
    unit_type_enum get_type() const noexcept { return header.type; }
    bool is_dummy() const noexcept { return header.type == unit_type_enum::dummy; }
    bool is_control_session() const noexcept {
        return header.type == unit_type::unit_type_enum::session_request
               || header.type == unit_type::unit_type_enum::session_created
               || header.type == unit_type::unit_type_enum::session_confirmed
               || header.type == unit_type::unit_type_enum::session_retry;
    }

private:
    header_data_type                                           header;
    noheap::buffer_bytes_type<buffer_data_size, noheap::rbyte> buffer;
};

// Packet(Batch)
struct [[gnu::packed]] extention_payload_data_type {
public:
    template<typename Self>
    decltype(auto) get_last_unit(this Self &&_this) noexcept {
        return _this.units[batch_units_number - 1];
    }
    template<typename Self>
    decltype(auto) get_control_unit(this Self &&_this) noexcept {
        return _this.units[control_unit_number - 1];
    }
    bool is_control_session_packet_type() const noexcept {
        return get_control_unit().is_control_session();
    }
    bool is_dummy() const noexcept {
        return (units[0].header.type == units[1].header.type
                && units[1].header.type == units[2].header.type
                && units[2].header.type == units[3].header.type
                && units[3].header.type == unit_type::unit_type_enum::dummy);
    }
    bool is_handshake() const noexcept {
        return is_control_session_packet_type() && units[0].is_dummy()
               && units[1].is_dummy() && units[3].is_dummy();
    }
    bool is_posthandshake() const noexcept {
        return (get_control_unit().is_dummy()
                || get_control_unit().header.type == unit_type::unit_type_enum::session_retry)
               && !units[0].is_control_session() && !units[1].is_control_session()
               && units[3].is_dummy();
    }

public:
    noheap::buffer_type<unit_type, batch_units_number> units;
};
static_assert(sizeof(extention_payload_data_type) == packet_size, "Invalid packet size.");

struct session_info_type;
struct session_info_type_extended;
class protocol;
class session_handler;
using packet_type = network::packet_native_type<extention_payload_data_type>;

template<typename T>
concept Packet_type = std::same_as<std::decay_t<T>, packet_type>;

class base_error : public noheap::runtime_error {
protected:
    using runtime_error::runtime_error;
};
class protocol_error : public base_error {
public:
    using base_error::base_error;
};
class session_error : public base_error {
public:
    using base_error::base_error;
};

} // namespace essu
#endif
