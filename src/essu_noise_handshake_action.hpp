#include "essu_protocol.hpp"

namespace essu {

// Noise handshake action for establishing shared secret key
struct noise_handshake_action : public network::action<essu::packet_type> {
public:
    using noise_context_type = essu::unit_type::noise_context_type;

public:
    void init_packet(packet_type &pckt);
    void process_packet(packet_type &&pckt);

public:
    noise::noise_action                                        get_action();
    typename noise_context_type::buffer_handshake_payload_type get_handshake_payload();
    typename noise_context_type::hash_state::buffer_type       get_handshake_hash();

public:
    void init(noise::noise_role role, noise_context_type::prologue_extention_type ext,
              const noise_context_type::keypair_type        &local_keypair,
              const noise_context_type::dh_key_type         &remote_public_key,
              const noise_context_type::pre_shared_key_type &pre_shared_key,
              const noise_context_type::dh_key_type         &_ephemeral_obfs_key);
    noise_context_type::cipher_state dump();

private:
    void check_noise_action(noise::noise_action expected);

private:
    noise_context_type noise_ctx;
    std::size_t        number_handshake_parts;

    typename noise_context_type::buffer_handshake_packet_type noise_handshake_packet{};
    noise_context_type::dh_key_type                           ephemeral_obfs_key;

    std::size_t offset_noise_handshake_unit;
    bool        fragmentation;

    typename noise_context_type::buffer_handshake_payload_type noise_handshake_payload;
    typename noise_context_type::hash_state::buffer_type       noise_handshake_hash;
};

} // namespace essu

void essu::noise_handshake_action::init_packet(packet_type &pckt) {
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
void essu::noise_handshake_action::process_packet(packet_type &&pckt) {
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
        {noise_handshake_packet.data(), offset_noise_handshake_unit}, payload_data_size);
    noise_ctx.get_handshake_message();

    noise_handshake_packet      = {};
    offset_noise_handshake_unit = 0;
    ++number_handshake_parts;
}

noise::noise_action essu::noise_handshake_action::get_action() {
    return fragmentation ? noise::noise_action::WRITE_MESSAGE : noise_ctx.get_action();
}
typename essu::noise_handshake_action::noise_context_type::buffer_handshake_payload_type
    essu::noise_handshake_action::get_handshake_payload() {
    return noise_handshake_payload;
}
typename essu::noise_handshake_action::noise_context_type::hash_state::buffer_type
    essu::noise_handshake_action::get_handshake_hash() {
    return noise_handshake_hash;
}

void essu::noise_handshake_action::init(
    noise::noise_role role, noise_context_type::prologue_extention_type ext,
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
essu::noise_handshake_action::noise_context_type::cipher_state
    essu::noise_handshake_action::dump() {
    noise_ctx.stop();

    noise_handshake_hash  = noise_ctx.get_handshake_hash();
    auto cipher_state_tmp = noise_ctx.get_cipher_state();
    noise_ctx.dump();

    return cipher_state_tmp;
}

void essu::noise_handshake_action::check_noise_action(noise::noise_action expected) {
    auto action = noise_ctx.get_action();
    if (action == noise::noise_action::FAILED)
        throw noheap::runtime_error("Failed to handshake.");
    else if (number_handshake_parts > 2)
        throw noheap::runtime_error("Unexpected behaviour during the noise handshake.");

    if (action == expected)
        return;

    if (action == noise::noise_action::WRITE_MESSAGE)
        throw noheap::runtime_error("Expected message to be sent.");
    else if (action == noise::noise_action::READ_MESSAGE)
        throw noheap::runtime_error("Expected message to be received.");
    else
        throw noheap::runtime_error("Handshake already completed.");
}
