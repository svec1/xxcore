#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include "audio_flow.hpp"
#include "crypto.hpp"
#include "net.hpp"
#include "noise.hpp"

namespace protocol {

using ad_type = std::size_t;

static constexpr std::size_t max_internal_data_size       = 256 - sizeof(ad_type);
static constexpr std::size_t max_payload_data_size        = 512 - sizeof(ad_type);
static constexpr std::size_t max_jitter_size              = 64;
static constexpr std::size_t min_count_packets_for_handle = max_jitter_size / 2;

static constexpr std::size_t max_count_contributers = 4;
static constexpr std::size_t uuid_size              = 8;
static constexpr std::byte   local_payload_value    = static_cast<std::byte>(
    (stream_audio::default_base_audio::cfg.sample_rate
     + stream_audio::default_base_audio::cfg.bitrate
     + (stream_audio::default_base_audio::cfg.channels * 1000) / 1000));

using uuid_type  = noheap::buffer_type<char, uuid_size>;
using uuids_type = std::array<uuid_type, max_count_contributers>;

// Udp payload packet
struct extention_payload_data_type {
    struct payload_data_type {
        using audio_buffer_type = stream_audio::encode_buffer_type;

    public:
        audio_buffer_type audio_buffer;

        uuids_type    uuids;
        std::uint16_t sequence_number;
        std::byte     payload_type;
        bool          lost;
    };

public:
    payload_data_type payload;

    noheap::buffer_bytes_type<max_payload_data_size - sizeof(payload_data_type)>
        padding{};
};

// Protected tcp payload packet
struct extention_internal_data_type {
    enum class data_type {
        OK = 0,
        FAIL,
        CHANGE_KEY,
    };

public:
    data_type type;

    noheap::buffer_bytes_type<max_internal_data_size - sizeof(data_type)> payload;
};

template<ntn_relation relation_type>
using noise_context_type   = noise_context<relation_type>;
using payload_packet_type  = packet_native_type<extention_payload_data_type, ad_type>;
using internal_packet_type = packet_native_type<extention_internal_data_type, ad_type>;
using noise_handshake_packet_type = packet_native_type<
    noise_context_type<ntn_relation::PTU>::buffer_handshake_packet_type, ad_type>;

// Payload protocol for sending a udp payload packets
struct payload_protocol_type
    : public protocol_native_type<payload_packet_type,
                                  noheap::log_impl::create_owner("VOICE_PROTOCOL")> {
    using packet_type        = payload_protocol_type::packet_type;
    using noise_context_type = noise_context_type<ntn_relation::PTU>;

    static constexpr auto cipher_algorithm = crypto::cipher_algorithm::CHACHA20_POLY1305;

public:
    constexpr void
        prepare(packet_type &pckt, buffer_address_type addr,
                payload_protocol_type::callback_prepare_type callback) const override {
        try {
            callback(pckt);

            pckt->payload.sequence_number = local_sequence_number++;
            pckt->payload.payload_type    = local_payload_value;
            pckt->payload.uuids[0]        = uuid;
            pckt->payload.lost            = false;

            pckt.payload_ad = sizeof(pckt->payload);

            // Encrypt the packet using established key(buffer_key)
            crypto::encrypt<cipher_algorithm>(
                {reinterpret_cast<noheap::ubyte *>(pckt.extention_data()),
                 pckt.extention_size()},
                pckt.payload_ad, buffer_key);

        } catch (noheap::runtime_error &excp) {
            excp.set_owner(buffer_owner);
            throw;
        }
    }
    constexpr void
        handle(packet_type &pckt, buffer_address_type addr,
               payload_protocol_type::callback_handle_type callback) const override {
        try {
            // Decrypt the packet using established key(buffer_key)
            crypto::decrypt<cipher_algorithm>(
                {reinterpret_cast<noheap::ubyte *>(pckt.extention_data()),
                 pckt.extention_size()},
                pckt.payload_ad, buffer_key);

            buffer.push(pckt, pckt->payload.sequence_number);

            if (buffer.get_count_elements() == min_count_packets_for_handle)
                filled = true;
            else if (!buffer.get_count_elements())
                filled = false;

            // Gets packet from jitter buffer and calls callback(push to audio flow)
            if (filled) {
                auto jitter_element                = buffer.pop();
                jitter_element.first->payload.lost = jitter_element.second;

                callback(std::move(jitter_element.first));
            }
        } catch (noheap::runtime_error &excp) {
            excp.set_owner(buffer_owner);
            throw;
        }
    }

public:
    void set_buffer_key(crypto::cipher<cipher_algorithm>::key_type &&_buffer_key) const {
        buffer_key = std::move(_buffer_key);
    }
    void set_local_sequence_number(std::uint16_t _local_sequence_number) const {
        local_sequence_number = _local_sequence_number;
    }
    void set_uuid(uuid_type &&_uuid) const { uuid = std::move(_uuid); }

public:
    float get_loss_per_cent() const {
        std::size_t count_pushed_packets = buffer.get_count_pushed_elements();
        std::size_t count_lost_packets   = buffer.get_count_lost_elements();

        float loss_per_cent =
            static_cast<float>(count_lost_packets - last_count_lost_packets)
            / (count_pushed_packets - last_count_pushed_packets);

        last_count_pushed_packets = count_pushed_packets;
        last_count_lost_packets   = count_lost_packets;

        return loss_per_cent;
    }

private:
    mutable crypto::cipher<cipher_algorithm>::key_type          buffer_key;
    mutable noheap::jitter_buffer<packet_type, max_jitter_size> buffer;

    mutable bool filled = false;

    mutable uuid_type     uuid;
    mutable std::uint32_t local_sequence_number;

    mutable std::size_t last_count_lost_packets   = 0;
    mutable std::size_t last_count_pushed_packets = 0;
};

// Noise handshake protocol for establishing shared secret key.
template<ntn_relation relation_type>
struct noise_handshake_protocol_type
    : public protocol_native_type<noise_handshake_packet_type,
                                  noheap::log_impl::create_owner(
                                      "NOISE_HANDSHAKE_PROTOCOL")> {
    using noise_context_type = noise_context_type<relation_type>;

public:
    constexpr void prepare(packet_type &pckt, buffer_address_type addr,
                           callback_prepare_type callback) const override {
        check_noise_action(noise_action::WRITE_MESSAGE);

        try {
            // Gets noise message for establishing noise handshake.
            noise_ctx_p->get_handshake_buffer().set(
                std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t *>(pckt.extention_data()),
                    pckt.extention_size()),
                0);
            noise_ctx_p->set_handshake_message();

            pckt.payload_ad = noise_ctx_p->get_handshake_buffer().get().size;
        } catch (noheap::runtime_error &excp) {
            excp.set_owner(buffer_owner);
            throw;
        }
    }
    constexpr void handle(packet_type &pckt, buffer_address_type addr,
                          callback_handle_type callback) const override {
        check_noise_action(noise_action::READ_MESSAGE);
        try {
            // Sets noise message.
            noise_ctx_p->get_handshake_buffer().set(
                std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t *>(pckt.extention_data()),
                    pckt.extention_size()),
                pckt.payload_ad);
            noise_ctx_p->get_handshake_message();
        } catch (noheap::runtime_error &excp) {
            excp.set_owner(buffer_owner);
            throw;
        }
    }

public:
    void set_noise_context(noise_context_type &noise_ctx) const {
        noise_ctx_p = &noise_ctx;
    }
    noise_context_type &get_noise_context() const {
        check_noise_ctx_p();
        return *noise_ctx_p;
    }

private:
    void check_noise_action(noise_action expected) const {
        check_noise_ctx_p();
        auto action = noise_ctx_p->get_action();
        if (action == noise_action::FAILED)
            throw noheap::runtime_error(buffer_owner, "Failed to handshake.");

        if (action == expected)
            return;

        if (action == noise_action::WRITE_MESSAGE)
            throw noheap::runtime_error(buffer_owner, "Expected message to be sent.");
        else if (action == noise_action::READ_MESSAGE)
            throw noheap::runtime_error(buffer_owner, "Expected message to be received.");
        else
            throw noheap::runtime_error(buffer_owner, "Handshake already completed.");
    }

    void check_noise_ctx_p() const {
        if (!noise_ctx_p)
            noheap::runtime_error(buffer_owner, "Noise context is null.");
    }

private:
    mutable noise_context_type *noise_ctx_p;
};

// Internal protocol on tcp connection. Designed to control the udp stream.
template<crypto::cipher_algorithm cipher_algorithm>
struct internal_protocol_type
    : public protocol_native_type<internal_packet_type,
                                  noheap::log_impl::create_owner("INTERNAL_PROTOCOL")> {
    using packet_type = internal_protocol_type::packet_type;

public:
    constexpr void prepare(packet_type &pckt, buffer_address_type addr,
                           callback_prepare_type callback) const override {
        std::size_t payload_size;

        // Checks the current type of data
        if (data_type == packet_type::extention_data_type::data_type::CHANGE_KEY) {
            buffer_key   = noheap::get_random_bytes<decltype(buffer_key)>();
            payload_size = sizeof(buffer_key);
        } else
            throw noheap::runtime_error(buffer_owner, "Invalid data type.");

        pckt->type = data_type;
        std::copy(buffer_key.begin(), buffer_key.end(), pckt->payload.begin());

        cipher_state->input_buffer.set(
            {reinterpret_cast<std::uint8_t *>(pckt.extention_data()),
             pckt.extention_size()},
            payload_size);
        cipher_state->encrypt();

        pckt.payload_ad = cipher_state->input_buffer.get().size;
    }
    constexpr void handle(packet_type &pckt, buffer_address_type addr,
                          callback_handle_type callback) const override {
        cipher_state->output_buffer.set(
            {reinterpret_cast<std::uint8_t *>(pckt.extention_data()),
             pckt.extention_size()},
            pckt.payload_ad);
        cipher_state->decrypt();

        if (data_type == packet_type::extention_data_type::data_type::CHANGE_KEY) {
            std::copy(pckt->payload.begin(), pckt->payload.begin() + sizeof(buffer_key),
                      buffer_key.begin());
        } else if (pckt->type == packet_type::extention_data_type::data_type::FAIL)
            throw noheap::runtime_error(buffer_owner, "Protocol fail.");
    }

public:
    void set_data_type(packet_type::extention_data_type::data_type _data_type) {
        data_type = _data_type;
    }

    auto get_buffer_key() const { return buffer_key; }

private:
    mutable crypto::cipher<cipher_algorithm>::key_type               buffer_key;
    mutable packet_type::extention_data_type::data_type              data_type;
    mutable noise_context_type<ntn_relation::UNKNOWN>::cipher_state *cipher_state;
};

struct payload_action final : action<payload_packet_type> {
    static constexpr std::size_t max_stream_size = max_jitter_size;

public:
    constexpr void init_packet(packet_type &pckt) override {
        audio.pop(pckt->payload.audio_buffer);
    }
    constexpr void process_packet(packet_type &&pckt) override {
        audio.push(std::move(pckt->payload.audio_buffer), pckt->payload.lost);
    }

private:
    audio_flow<max_stream_size> audio;
};

struct noise_handshake_action final : public decoy_action<noise_handshake_packet_type> {};
struct internal_action final : public decoy_action<internal_packet_type> {};

template<ntn_relation relation_type>
using noise_handshake_packet =
    packet<noise_handshake_packet_type, noise_handshake_protocol_type<relation_type>>;
using payload_packet = packet<payload_packet_type, payload_protocol_type>;
using internal_packet =
    packet<internal_packet_type,
           internal_protocol_type<payload_packet::protocol_type::cipher_algorithm>>;

} // namespace protocol

#endif
