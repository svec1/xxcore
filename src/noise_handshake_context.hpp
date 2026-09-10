#ifndef NOISE_HANDSHAKE_CONTEXT_HPP
#define NOISE_HANDSHAKE_CONTEXT_HPP

#include "noise.hpp"

// Noise handshake context for establishing shared secret key
template<noise::noise_context_config _config>
struct noise_handshake_context {
    static constexpr noise::noise_context_config config = _config;
    using noise_context_type                            = noise::noise_context<config>;

private:
    using buffer_unique_value_type =
        noise::buffer_type<config.nonce_size * 2 + sizeof(std::uint64_t)
                           + sizeof(std::uint16_t)>;

public:
    enum class status_enum : std::size_t {
        HS1 = 0,
        HS2,
        HS3,
        NEEDS_COMPLETE,
        COMPLETE,
    };

public:
    static constexpr noise::hash_type config_hash_type = config.hash;
    static constexpr noise::hash_type current_state_hash_type =
        noise::hash_type::RIPEMD160;

    using buffer_config_hash_type =
        typename noise_context_type::template hash_state<config_hash_type>::buffer_type;
    using buffer_current_state_hash_type =
        typename noise_context_type::template hash_state<
            current_state_hash_type>::buffer_type;

public:
    inline noise_handshake_context(
        noise::noise_role _role, noise::buffer_prologue_extention_type _ext,
        const noise_context_type::buffer_key_type &_remote_public_key,
        const noise::buffer_pre_shared_key_type   &_pre_shared_key,
        const noise_context_type::keypair_type    &_local_keypair);
    inline noise_handshake_context(noise_handshake_context &&) = default;

public:
    template<noheap::Buffer_bytes TBuffer>
    inline void init_packet(TBuffer &buffer);
    template<noheap::Buffer_bytes TBuffer>
    inline void handle_packet(TBuffer &&buffer);

    inline status_enum                                get_status() const noexcept;
    inline noise::noise_role                          get_role() const;
    inline noise::noise_action                        get_action() const;
    inline std::uint16_t                              get_available_batch_number() const;
    inline std::uint64_t                              get_handshake_id() const;
    inline buffer_current_state_hash_type             get_current_state_hash() const;
    inline const noise_context_type::buffer_key_type &get_remote_public_key() const;
    inline typename noise_context_type::template hash_state<config_hash_type>                                               &
        get_hash_state();
    inline typename noise_context_type::cipher_state &get_payload_cipher_state();
    inline typename noise_context_type::cipher_state &get_header_cipher_state_sender();
    inline typename noise_context_type::cipher_state &get_header_cipher_state_receiver();
    inline typename noise_context_type::random_state &get_random_state();

    inline void start();
    inline void stop();

    template<std::size_t buffer_size>
    static inline noise::buffer_type<buffer_size> derive_header_obfs_key(
        typename noise_handshake_context::noise_context_type::cipher_state
            &header_cipher_state);

private:
    inline void check_noise_action(noise::noise_action expected);
    inline void generate_pair_ephemeral_obfs_key();
    inline void generate_posthandshake_unique_values();
    inline void update_current_state_hash();

private:
    status_enum status;

    noise_context_type                        noise_context;
    typename noise_context_type::cipher_state payload_cipher_state;
    typename noise_context_type::cipher_state header_cipher_state_sender;
    typename noise_context_type::cipher_state header_cipher_state_receiver;
    typename noise_context_type::random_state random_state;
    noise_context_type::template hash_state<config_hash_type> hash_state;
    noise_context_type::template hash_state<current_state_hash_type>
        current_state_hash_state;

    noise::noise_role                       role;
    noise::buffer_prologue_extention_type   ext;
    noise_context_type::buffer_key_type     remote_public_key;
    noise::buffer_pre_shared_key_type       pre_shared_key;
    const noise_context_type::keypair_type &local_keypair;

    typename noise::buffer_handshake_packet_type buffer_handshake_message{};
    std::size_t                                  offset_noise_handshake_unit{};
    bool                                         fragmentation{};

    typename noise::buffer_handshake_payload_type handshake_payload{};
    buffer_config_hash_type                       handshake_hash{};
    buffer_unique_value_type                      unique_value{};
    std::uint16_t                                 available_batch_number{};
    std::uint64_t                                 handshake_id{};
    std::uint16_t                                 handshake_attempt_number{};
};

template<noise::noise_context_config _config>
noise_handshake_context<_config>::noise_handshake_context(
    noise::noise_role _role, noise::buffer_prologue_extention_type _ext,
    const noise_context_type::buffer_key_type &_remote_public_key,
    const noise::buffer_pre_shared_key_type   &_pre_shared_key,
    const noise_context_type::keypair_type    &_local_keypair)
    : role(_role), ext(_ext), remote_public_key(_remote_public_key),
      pre_shared_key(_pre_shared_key), local_keypair(_local_keypair) {
}

template<noise::noise_context_config _config>
template<noheap::Buffer_bytes TBuffer>
void noise_handshake_context<_config>::noise_handshake_context::init_packet(
    TBuffer &buffer) {
    check_noise_action(noise::noise_action::WRITE_MESSAGE);

    if (!fragmentation) {
        // Generates random value
        if (status == status_enum::HS3) {
            random_state.padding_buffer.set(handshake_payload, 0);
            random_state.pad();
            noise_context.get_handshake_payload_buffer().set(handshake_payload,
                                                             handshake_payload.size());
        }

        // Gets noise message
        try {
            noise_context.get_handshake_buffer().set(buffer_handshake_message, 0);
            noise_context.set_handshake_message();
        } catch (const noheap::runtime_error &excp) {
            throw noheap::runtime_error("Failed to set handshake message: {}",
                                        excp.what());
        }
    }

    // Copy payload of the noise message
    std::copy(buffer_handshake_message.begin() + offset_noise_handshake_unit,
              buffer_handshake_message.begin() + offset_noise_handshake_unit
                  + buffer.size(),
              reinterpret_cast<noheap::rbyte *>(buffer.begin()));
    offset_noise_handshake_unit += buffer.size();

    // If fragmentation
    if (offset_noise_handshake_unit < noise_context.get_handshake_buffer().get().size) {
        fragmentation = true;
        return;
    }

    std::size_t occupied_bytes = (noise_context.get_handshake_buffer().get().size
                                  - (offset_noise_handshake_unit - buffer.size()));
    random_state.padding_buffer.set({buffer.data(), buffer.size()}, occupied_bytes);
    random_state.pad();

    buffer_handshake_message    = {};
    offset_noise_handshake_unit = 0;
    fragmentation               = false;
    status                      = status_enum(static_cast<std::size_t>(status) + 1);
}
template<noise::noise_context_config _config>
template<noheap::Buffer_bytes TBuffer>
void noise_handshake_context<_config>::noise_handshake_context::handle_packet(
    TBuffer &&buffer) {
    check_noise_action(noise::noise_action::READ_MESSAGE);

    // Determines size of payload data
    std::uint64_t payload_size = 0;
    if (status == status_enum::HS1)
        payload_size = config.get_hs1_size();
    else if (status == status_enum::HS2)
        payload_size = config.get_hs2_size();
    else if (status == status_enum::HS3)
        payload_size = config.get_hs3_size();
    else
        abort_invalid_state();

    // Copies accepted unit to buffer of noise handshake message
    std::copy(buffer.begin(), buffer.end(),
              buffer_handshake_message.begin() + offset_noise_handshake_unit);
    offset_noise_handshake_unit += buffer.size();

    // If fragmentation
    if (payload_size > offset_noise_handshake_unit)
        return;

    if (status == status_enum::HS3)
        // Sets buffer to get random value
        noise_context.get_handshake_payload_buffer().set(handshake_payload, 0);

    // Sets noise message
    try {
        noise_context.get_handshake_buffer().set(buffer_handshake_message, payload_size);
        noise_context.get_handshake_message();
    } catch (const noheap::runtime_error &excp) {
        throw noheap::runtime_error("Failed to get handshake message{}", excp.what());
    }

    buffer_handshake_message    = {};
    offset_noise_handshake_unit = 0;
    status                      = status_enum(static_cast<std::size_t>(status) + 1);
}

template<noise::noise_context_config _config>
typename noise_handshake_context<_config>::noise_context_type::cipher_state &
    noise_handshake_context<_config>::get_payload_cipher_state() {
    return payload_cipher_state;
}
template<noise::noise_context_config _config>
typename noise_handshake_context<_config>::noise_context_type::cipher_state &
    noise_handshake_context<_config>::get_header_cipher_state_sender() {
    return header_cipher_state_sender;
}
template<noise::noise_context_config _config>
typename noise_handshake_context<_config>::noise_context_type::cipher_state &
    noise_handshake_context<_config>::get_header_cipher_state_receiver() {
    return header_cipher_state_receiver;
}
template<noise::noise_context_config _config>
typename noise_handshake_context<_config>::noise_context_type::template hash_state<
    noise_handshake_context<_config>::config_hash_type> &
    noise_handshake_context<_config>::get_hash_state() {
    return hash_state;
}
template<noise::noise_context_config _config>
typename noise_handshake_context<_config>::noise_context_type::random_state &
    noise_handshake_context<_config>::get_random_state() {
    return random_state;
}
template<noise::noise_context_config _config>
noise_handshake_context<_config>::status_enum
    noise_handshake_context<_config>::get_status() const noexcept {
    return status;
}
template<noise::noise_context_config _config>
noise::noise_role noise_handshake_context<_config>::get_role() const {
    return noise_context.get_role();
}
template<noise::noise_context_config _config>
noise::noise_action noise_handshake_context<_config>::get_action() const {
    return fragmentation ? noise::noise_action::WRITE_MESSAGE
                         : noise_context.get_action();
}
template<noise::noise_context_config _config>
std::uint16_t noise_handshake_context<_config>::get_available_batch_number() const {
    return available_batch_number;
}
template<noise::noise_context_config _config>
noise_handshake_context<_config>::buffer_current_state_hash_type
    noise_handshake_context<_config>::get_current_state_hash() const {
    buffer_current_state_hash_type current_state_hash{};

    noheap::transform_buffers(current_state_hash, ext, std::bit_xor{});
    noheap::transform_buffers(current_state_hash, remote_public_key, std::bit_xor{});
    noheap::transform_buffers(current_state_hash, pre_shared_key, std::bit_xor{});
    noheap::transform_buffers(current_state_hash, unique_value, std::bit_xor{});
    noheap::transform_buffers(
        current_state_hash,
        noheap::to_buffer<const noheap::buffer_bytes_type<sizeof(available_batch_number),
                                                          noheap::rbyte>>(
            available_batch_number),
        std::bit_xor{});
    noheap::transform_buffers(
        current_state_hash,
        noheap::to_buffer<
            const noheap::buffer_bytes_type<sizeof(handshake_id), noheap::rbyte>>(
            handshake_id),
        std::bit_xor{});

    return current_state_hash_state.get_hash(hash_state.get_hash(current_state_hash));
}
template<noise::noise_context_config _config>
std::uint64_t noise_handshake_context<_config>::get_handshake_id() const {
    return handshake_id;
}
template<noise::noise_context_config _config>
const noise_handshake_context<_config>::noise_context_type::buffer_key_type &
    noise_handshake_context<_config>::get_remote_public_key() const {
    return remote_public_key;
}

template<noise::noise_context_config _config>
void noise_handshake_context<_config>::start() {
    status                      = status_enum::HS1;
    offset_noise_handshake_unit = 0;
    fragmentation               = false;
    buffer_handshake_message    = {};
    handshake_payload           = {};
    handshake_hash              = {};
    available_batch_number      = 0;
    random_state.reseed();

    generate_pair_ephemeral_obfs_key();

    try {
        noise_context.init(role);
        noise_context.set_prologue(ext);
        noise_context.set_local_keypair(local_keypair);
        noise_context.set_remote_public_key(remote_public_key);
        noise_context.set_pre_shared_key(pre_shared_key);
        noise_context.start();
    } catch (const noheap::runtime_error &excp) {
        throw noheap::runtime_error("Failed to start handshake: {}", excp.what());
    }

    ++handshake_attempt_number;
}
template<noise::noise_context_config _config>
void noise_handshake_context<_config>::stop() {
    check_noise_action(noise::noise_action::SPLIT);

    // If local rpk is non empty it checks rpk from handshake, for XX pattern
    if (auto handshake_remote_public_key = noise_context.get_remote_public_key();
        handshake_remote_public_key != remote_public_key) {
        if (remote_public_key == noise_context_type::buffer_key_type{})
            remote_public_key = handshake_remote_public_key;
        else
            throw noheap::runtime_error("Invalid remote public key from handshake.");
    }

    try {
        noise_context.stop();
    } catch (const noheap::runtime_error &excp) {
        throw noheap::runtime_error("Failed to stop handshake: {}", excp.what());
    }
    payload_cipher_state = std::move(noise_context.get_cipher_state());
    handshake_hash       = noise_context.get_handshake_hash();
    generate_posthandshake_unique_values();

    noise_context.dump();

    status                   = status_enum(static_cast<std::size_t>(status) + 1);
    handshake_payload        = {};
    handshake_hash           = {};
    handshake_attempt_number = 0;
}
template<noise::noise_context_config _config>
void noise_handshake_context<_config>::check_noise_action(noise::noise_action expected) {
    auto action = noise_context.get_action();

    if (action == noise::noise_action::FAILED)
        throw noheap::runtime_error("Failed to handshake.");

    if (action == expected
        || (expected == noise::noise_action::WRITE_MESSAGE && fragmentation))
        return;

    if (action == noise::noise_action::WRITE_MESSAGE)
        throw noheap::runtime_error("Expected message to be sent.");
    else if (action == noise::noise_action::READ_MESSAGE)
        throw noheap::runtime_error("Expected message to be received.");
    else if (action == noise::noise_action::SPLIT)
        throw noheap::runtime_error("Expected to stop handshake.");
    else if (action == noise::noise_action::COMPLETE)
        throw noheap::runtime_error("Handshake already completed.");
    else if (action == noise::noise_action::NONE)
        throw noheap::runtime_error("Action is not required.");
    else
        abort_invalid_state();
}

// Generates ephemeral header obfuscation key + ephmeral obfuscation key for HS1
template<noise::noise_context_config _config>
void noise_handshake_context<_config>::generate_pair_ephemeral_obfs_key() {
    typename noise_context_type::cipher_state cipher_tmp;
    noise::buffer_type<noheap::buffer_size<typename noise_context_type::buffer_key_type>
                       + config.mac_size>
        shared_handshake_value{};
    noise::buffer_type<noheap::buffer_size<typename noise_context_type::buffer_key_type>
                           * 2
                       + sizeof(std::uint64_t) + config.mac_size>
        keystream{};

    // Mixes the shared_handshake_value with own and remote public keys
    if (remote_public_key != noise_context_type::buffer_key_type{}) {
        noheap::transform_buffers(shared_handshake_value, local_keypair.pub,
                                  std::bit_xor{});
        noheap::transform_buffers(shared_handshake_value, remote_public_key,
                                  std::bit_xor{});
    }

    // Encrypts shared_handshake_value with unique_value
    cipher_tmp.encrypt_buffer.set(shared_handshake_value,
                                  shared_handshake_value.size() - config.mac_size);
    cipher_tmp.set_encrypt_key(
        noheap::clip_buffer<32, 0>(hash_state.get_hash(unique_value)));
    cipher_tmp.set_encrypt_nonce({});
    cipher_tmp.set_encrypt_counter_block(handshake_attempt_number);
    cipher_tmp.encrypt({});

    // Generates keystream: encrypts keystream which is filled zeros with
    // shared_handshake_value
    cipher_tmp.encrypt_buffer.set(keystream, keystream.size() - config.mac_size);
    cipher_tmp.set_encrypt_key(
        noheap::clip_buffer<32, 0>(hash_state.get_hash(shared_handshake_value)));
    cipher_tmp.set_encrypt_nonce({});
    cipher_tmp.encrypt({});

    // Gets two ephemeral header obfuscation keys
    auto header_obfs_key1 = noheap::clip_buffer<
        noheap::buffer_size<typename noise_context_type::buffer_key_type>, 0>(keystream);
    auto header_obfs_key2 = noheap::clip_buffer<
        noheap::buffer_size<typename noise_context_type::buffer_key_type>,
        noheap::buffer_size<typename noise_context_type::buffer_key_type>>(keystream);

    // Sets these keys and reset nonces of header cipher states
    if (role == noise::noise_role::INITIATOR) {
        header_cipher_state_sender.set_encrypt_key(header_obfs_key1);
        header_cipher_state_receiver.set_encrypt_key(header_obfs_key2);
    } else {
        header_cipher_state_sender.set_encrypt_key(header_obfs_key2);
        header_cipher_state_receiver.set_encrypt_key(header_obfs_key1);
    }
    header_cipher_state_sender.set_encrypt_nonce({});
    header_cipher_state_receiver.set_encrypt_nonce({});

    // Sets available batch number and handshake id
    available_batch_number = 0;
    handshake_id ^= noheap::represent_bytes<std::uint64_t>(
        noheap::clip_buffer<
            sizeof(std::uint64_t),
            noheap::buffer_size<typename noise_context_type::buffer_key_type> * 2>(
            keystream));

    payload_cipher_state = {};
}

// Generates posthandshake header obfuscation key + unique value
template<noise::noise_context_config _config>
void noise_handshake_context<
    _config>::noise_handshake_context::generate_posthandshake_unique_values() {
    // Mixes the current handshake payload with the unique value
    noheap::transform_buffers(handshake_payload, unique_value, std::bit_xor{});

    // Generates unique values
    std::decay_t<decltype(handshake_hash)> unique_value_one, unique_value_two;
    hash_state.hkdf(handshake_hash, handshake_payload, unique_value_one,
                    unique_value_two);

    // Mixes the unique value with new
    noheap::transform_buffers(unique_value, unique_value_one, std::bit_xor{});

    // Handles the first unique_value
    {
        handshake_id ^= noheap::represent_bytes<std::uint64_t>(
            noheap::clip_buffer<sizeof(std::uint64_t), sizeof(std::uint16_t)>(
                unique_value));

        // Gets two nonce values
        typename noise_context_type::buffer_nonce_type value1 =
            noheap::represent_bytes<noise_context_type::buffer_nonce_type>(
                noheap::clip_buffer<
                    noheap::buffer_size<typename noise_context_type::buffer_nonce_type>,
                    sizeof(std::uint16_t) + sizeof(std::uint64_t)>(unique_value));
        typename noise_context_type::buffer_nonce_type value2 =
            noheap::represent_bytes<noise_context_type::buffer_nonce_type>(
                noheap::clip_buffer<
                    noheap::buffer_size<typename noise_context_type::buffer_nonce_type>,
                    sizeof(std::uint16_t) + sizeof(std::uint64_t)
                        + noheap::buffer_size<
                            typename noise_context_type::buffer_nonce_type>>(
                    unique_value));

        // Sets these nonce values
        if (noise_context.get_role() == noise::noise_role::INITIATOR) {
            payload_cipher_state.set_encrypt_nonce(value1);
            payload_cipher_state.set_decrypt_nonce(value2);
        } else {
            payload_cipher_state.set_encrypt_nonce(value2);
            payload_cipher_state.set_decrypt_nonce(value1);
        }
    }

    // Handles the second unique_value
    {
        // Generates keystream - the header obfuscation key
        noise::buffer_type<
            noheap::buffer_size<typename noise_context_type::buffer_key_type> * 2
            + config.mac_size>
                                                  keystream{};
        typename noise_context_type::cipher_state cipher_tmp;
        cipher_tmp.set_encrypt_key(
            noheap::clip_buffer<
                noheap::buffer_size<typename noise_context_type::buffer_key_type>, 0>(
                unique_value_two));
        cipher_tmp.encrypt_buffer.set(keystream, keystream.size() - config.mac_size);
        cipher_tmp.encrypt({});

        // Gets two header obfuscation keys
        auto header_obfs_key1 = noheap::clip_buffer<
            noheap::buffer_size<typename noise_context_type::buffer_key_type>, 0>(
            keystream);
        auto header_obfs_key2 = noheap::clip_buffer<
            noheap::buffer_size<typename noise_context_type::buffer_key_type>,
            noheap::buffer_size<typename noise_context_type::buffer_key_type>>(keystream);

        // Sets these keys and reset nonces of header cipher states
        if (role == noise::noise_role::INITIATOR) {
            header_cipher_state_sender.set_encrypt_key(header_obfs_key1);
            header_cipher_state_receiver.set_encrypt_key(header_obfs_key2);
        } else {
            header_cipher_state_sender.set_encrypt_key(header_obfs_key2);
            header_cipher_state_receiver.set_encrypt_key(header_obfs_key1);
        }
        header_cipher_state_sender.set_encrypt_nonce({});
        header_cipher_state_receiver.set_encrypt_nonce({});
    }
}
template<noise::noise_context_config _config>
template<std::size_t buffer_size>
noise::buffer_type<buffer_size> noise_handshake_context<_config>::derive_header_obfs_key(
    typename noise_handshake_context::noise_context_type::cipher_state
        &header_cipher_state) {
    noise::buffer_type<buffer_size + config.mac_size> obfs_key_tmp{};
    header_cipher_state.encrypt_buffer.set(obfs_key_tmp,
                                           obfs_key_tmp.size() - config.mac_size);
    header_cipher_state.encrypt({});

    return noheap::to_buffer<decltype(derive_header_obfs_key(header_cipher_state))>(
        obfs_key_tmp);
}

#endif
