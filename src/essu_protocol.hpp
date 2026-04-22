#ifndef ESSU_HPP
#define ESSU_HPP

#include "essu_base.hpp"
#include "essu_noise_handshake_context.hpp"

namespace essu {

// Session info corresponding to an individual node
struct session_info_type {
    friend class protocol_type;

private:
    enum class status_enum : std::size_t {
        hs1,
        hs2,
        hs3,
        is_connected,
    };

public:
    session_info_type(network::buffer_address_type _addr) : addr(_addr) {
        reset_numbers();
    }

private:
    void reset_numbers() {
        status                        = status_enum::hs1;
        batches_sent_number           = 0;
        sender_units_number           = 0;
        receiver_units_number         = 0;
        sender_key_iteration_number   = 0;
        receiver_key_iteration_number = 0;
        undecrypted_batch_number      = 0;
    }

public:
    const network::buffer_address_type addr;
    std::uint64_t                      id;

private:
    noise_handshake_context handshake_context;

    status_enum status;
    std::size_t batches_sent_number;
    std::size_t sender_units_number;
    std::size_t receiver_units_number;
    std::size_t sender_key_iteration_number;
    std::size_t receiver_key_iteration_number;
    std::size_t undecrypted_batch_number;
};

struct protocol_type
    : public network::protocol_native_type<packet_type, noheap::log_impl::create_owner(
                                                            "ESSU_PROTOCOL")> {
    using session_info_s_type =
        noheap::monotonic_array<session_info_type *, network::max_count_addresses>;

public:
    void prepare(packet_type &pckt, network::buffer_address_type addr,
                 protocol_type::callback_prepare_type callback) const;
    void handle(packet_type &pckt, network::buffer_address_type addr,
                protocol_type::callback_handle_type callback) const;

public:
    void register_session_info(
        session_info_type &session_info, noise::noise_role role,
        noise::prologue_extention_type          ext,
        const noise::pre_shared_key_type       &pre_shared_key,
        const noise_context_type::keypair_type &local_keypair,
        const noise_context_type::dh_key_type  &remote_public_key) const;
    void start_handshake(session_info_type &session_info) const;
    void stop_handshake(session_info_type &session_info) const;

    bool                needs_to_rehandshake(const session_info_type &session_info) const;
    noise::noise_action get_handshake_action(const session_info_type &session_info) const;

private:
    session_info_s_type::iterator
         find_session_info(network::buffer_address_type addr) const;
    void update_protocol_status(session_info_type &session_info,
                                const unit_type   &unit) const;
    noise::buffer_type<sizeof(typename unit_type::header_data_type)>
        derive_header_obfs_key(
            typename noise_context_type::cipher_state &header_cipher_state,
            std::uint32_t                              number) const;

private:
    mutable session_info_s_type session_info_s;
};

using wrapper_packet_type = network::wrapper_packet<packet_type, protocol_type>;

} // namespace essu

void essu::protocol_type::prepare(packet_type &pckt, network::buffer_address_type addr,
                                  protocol_type::callback_prepare_type callback) const {
    try {
        auto session_info_it = find_session_info(addr);
        if (session_info_it == session_info_s.end())
            throw noheap::runtime_error("Not found session info.");
        decltype(auto) session_info = *(*session_info_it);

        // Updates protocol status of passed session
        update_protocol_status(session_info, pckt->units[0]);

        // Calls callback(action) to init packet
        if (session_info.status == session_info_type::status_enum::is_connected)
            callback(pckt);
        else
            session_info.handshake_context.init_packet(pckt);

        decltype(auto) payload_cipher_state =
            session_info.handshake_context.get_payload_cipher_state();
        decltype(auto) header_cipher_state =
            session_info.handshake_context.get_header_cipher_state();

        // Performs rekey for encryption
        ++session_info.batches_sent_number;
        if (payload_cipher_state.valid()
            && session_info.batches_sent_number % batches_per_rekey_number == 0) {
            payload_cipher_state.rekey_encrypt();
            ++session_info.sender_key_iteration_number;
        }

        for (std::size_t i = 0; i < pckt->units.size(); ++i) {
            unit_type &unit = pckt->units[i];

            unit.header.number               = session_info.sender_units_number++;
            unit.header.key_iteration_number = session_info.sender_key_iteration_number;

            // Forces units to be dummy if necessary
            if (i >= 2) {
                unit.header.type = unit_type::unit_type_enum::data;
                unit.header.flag = unit_type::flag_type_enum::drop;
            }

            // Adds random padding
            {
                // Determines payload size of the unit to define size of random
                // padding
                std::size_t payload_size;
                if (unit.header.flag == unit_type::flag_type_enum::drop)
                    payload_size = 0;
                else {
                    switch (unit.header.type) {
                        case unit_type::unit_type_enum::session_request:
                            payload_size = unit_config_type::hs1_size
                                           - (unit.buffer.size() * unit.header.number);
                            break;
                        case unit_type::unit_type_enum::session_created:
                            payload_size = unit_config_type::hs2_size
                                           - (unit.buffer.size() * unit.header.number);
                            break;
                        case unit_type::unit_type_enum::session_confirmed:
                            payload_size = unit_config_type::hs3_size
                                           - (unit.buffer.size() * unit.header.number);
                            break;
                        case unit_type::unit_type_enum::data:
                            payload_size = payload_data_size;
                            break;
                        case unit_type::unit_type_enum::hole_punch:
                            payload_size = 8;
                            break;
                        default:
                            throw noheap::runtime_error(
                                buffer_owner, "Packet type[{}] is not allowed.",
                                static_cast<std::size_t>(unit.header.type));
                    }
                }

                // Adds random padding after payload data
                payload_cipher_state.input_buffer.set(
                    {reinterpret_cast<noheap::rbyte *>(unit.buffer.data()),
                     unit.buffer.size()},
                    std::clamp<std::size_t>(payload_size, 0, unit.buffer.size()));
                payload_cipher_state.pad();
            }

            // Encrypts buffer data and authenticates based on the header
            if (session_info.status == session_info_type::status_enum::is_connected
                && unit.header.type == unit_type::unit_type_enum::data) {
                payload_cipher_state.input_buffer.set(
                    {unit.buffer.data(), unit.buffer.size()},
                    unit.buffer_size_without_mac);
                payload_cipher_state.set_encrypt_nonce(unit.header.number);
                payload_cipher_state.encrypt(
                    {reinterpret_cast<noheap::rbyte *>(&unit.header),
                     sizeof(unit.header)});
            }

            // Generates header obfuscation key based on the unit_number
            auto obfs_key_tmp =
                derive_header_obfs_key(header_cipher_state, unit.header.number);

            // Adds header data obfuscation
            std::transform(
                reinterpret_cast<noheap::rbyte *>(&unit.header),
                reinterpret_cast<noheap::rbyte *>(&unit.header) + sizeof(unit.header),
                obfs_key_tmp.data(), reinterpret_cast<noheap::rbyte *>(&unit.header),
                std::bit_xor{});
        }

        // Shuffles units in batch
        std::random_device rd;
        std::mt19937       generator(rd());
        std::shuffle(pckt->units.begin(), pckt->units.end(), generator);

        // Checks limit of available batches after handshake
        if (session_info.batches_sent_number == max_available_batches_number) {
            session_info.reset_numbers();
            payload_cipher_state.dump();
        }

    } catch (noheap::runtime_error &excp) {
        excp.set_owner(this->buffer_owner);
        throw;
    }
}

void essu::protocol_type::handle(packet_type &pckt, network::buffer_address_type addr,
                                 protocol_type::callback_handle_type callback) const {
    try {
        auto session_info_it = find_session_info(addr);
        if (session_info_it == session_info_s.end())
            return;

        decltype(auto) session_info = *(*session_info_it);
        decltype(auto) payload_cipher_state =
            session_info.handshake_context.get_payload_cipher_state();
        decltype(auto) header_cipher_state =
            session_info.handshake_context.get_header_cipher_state();

        // Selects possible unit number
        std::size_t count_decrypted_units = 0;
        for (std::size_t possible_unit_number = session_info.receiver_units_number;
             possible_unit_number
             < session_info.receiver_units_number + batches_window_number;
             ++possible_unit_number) {
            // Generates header obfuscation key based on the possible_unit_number
            auto obfs_key_tmp =
                derive_header_obfs_key(header_cipher_state, possible_unit_number);

            for (auto &unit : pckt->units) {
                unit_type test_unit = unit;

                // Deletes header data obfuscation
                std::transform(reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                               reinterpret_cast<noheap::rbyte *>(&test_unit.header)
                                   + sizeof(test_unit.header),
                               obfs_key_tmp.data(),
                               reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                               std::bit_xor{});

                if (test_unit.header.number != possible_unit_number)
                    continue;

                // Loop handling rekeys performed on the remote node.
                for (; session_info.receiver_key_iteration_number
                       < test_unit.header.key_iteration_number;
                     ++session_info.receiver_key_iteration_number)
                    payload_cipher_state.rekey_decrypt();

                // Tries to decrypt buffer data
                if (session_info.status == session_info_type::status_enum::is_connected
                    && test_unit.header.type == unit_type::unit_type_enum::data) {
                    payload_cipher_state.output_buffer.set(
                        {test_unit.buffer.data(), test_unit.buffer.size()},
                        test_unit.buffer.size());
                    payload_cipher_state.set_decrypt_nonce(test_unit.header.number);
                    try {
                        payload_cipher_state.decrypt(
                            {reinterpret_cast<noheap::rbyte *>(&test_unit.header),
                             sizeof(test_unit.header)});
                    } catch (noheap::runtime_error &excp) {
                        continue;
                    }
                }

                unit = test_unit;
                ++count_decrypted_units;
                break;
            }

            if (count_decrypted_units == pckt->units.size())
                break;
        }

        // If it was not possible to decrypt all units in batch
        if (count_decrypted_units != pckt->units.size()) {
            ++session_info.undecrypted_batch_number;
            if (session_info.status != session_info_type::status_enum::is_connected
                || session_info.undecrypted_batch_number
                       == max_undecrypted_batches_number)
                throw noheap::runtime_error("Failed to decrypt last batches.");
            return;
        } else
            session_info.undecrypted_batch_number = 0;

        // Restores order of units in batch
        std::sort(pckt->units.begin(), pckt->units.end(),
                  [](const auto &el_left, const auto &el_right) {
                      return el_left.header.number < el_right.header.number;
                  });

        session_info.receiver_units_number =
            pckt->units[pckt->units.size() - 1].header.number + 1;

        update_protocol_status(session_info, pckt->units[0]);

        if (session_info.status == session_info_type::status_enum::is_connected)
            callback(std::move(pckt));
        else
            session_info.handshake_context.process_packet(std::move(pckt));
    } catch (noheap::runtime_error &excp) {
        excp.set_owner(this->buffer_owner);
        throw;
    }
};

void essu::protocol_type::register_session_info(
    session_info_type &session_info, noise::noise_role role,
    noise::prologue_extention_type ext, const noise::pre_shared_key_type &pre_shared_key,
    const noise_context_type::keypair_type &local_keypair,
    const noise_context_type::dh_key_type  &remote_public_key) const {
    if (find_session_info(session_info.addr) != session_info_s.end())
        throw noheap::runtime_error(this->buffer_owner, "Session already exist.");
    if (session_info_s.size() == network::max_count_addresses)
        throw noheap::runtime_error(this->buffer_owner,
                                    "Sessions limit has been reached.");

    const_cast<session_info_s_type &>(session_info_s).push_back(&session_info);

    session_info_s[session_info_s.size() - 1]->handshake_context =
        noise_handshake_context{role, ext, pre_shared_key, local_keypair,
                                remote_public_key};
}
void essu::protocol_type::start_handshake(session_info_type &session_info) const {
    session_info.handshake_context.start();
}
void essu::protocol_type::stop_handshake(session_info_type &session_info) const {
    session_info.handshake_context.stop();

    auto unique_value = session_info.handshake_context.get_unique_value();
    session_info.id   = noheap::represent_bytes<std::uint64_t>(
        noheap::clip_buffer<sizeof(std::uint64_t), 0>(unique_value));

    const std::uint32_t value1 = noheap::represent_bytes<std::uint32_t>(
        noheap::clip_buffer<sizeof(std::uint32_t), sizeof(std::uint64_t)>(unique_value));
    const std::uint32_t value2 = noheap::represent_bytes<std::uint32_t>(
        noheap::clip_buffer<sizeof(std::uint32_t),
                            sizeof(std::uint64_t) + sizeof(std::uint32_t)>(unique_value));

    if (session_info.handshake_context.get_role() == noise::noise_role::INITIATOR) {
        session_info.sender_units_number   = value1;
        session_info.receiver_units_number = value2;
    } else {
        session_info.sender_units_number   = value2;
        session_info.receiver_units_number = value1;
    }
}
bool essu::protocol_type::needs_to_rehandshake(
    const session_info_type &session_info) const {
    return session_info.batches_sent_number == max_available_batches_number;
}
noise::noise_action essu::protocol_type::get_handshake_action(
    const session_info_type &session_info) const {
    return session_info.handshake_context.get_action();
}

essu::protocol_type::session_info_s_type::iterator
    essu::protocol_type::find_session_info(network::buffer_address_type addr) const {
    return std::find_if(session_info_s.begin(), session_info_s.end(),
                        [&](auto el) { return el->addr == addr; });
}
void essu::protocol_type::update_protocol_status(session_info_type &session_info,
                                                 const unit_type   &unit) const {
    if (session_info.status == session_info_type::status_enum::hs1
        && unit.header.type != unit_type::unit_type_enum::session_request)
        throw noheap::runtime_error("Expected session request unit.");
    else if (session_info.status == session_info_type::status_enum::hs2
             && unit.header.type != unit_type::unit_type_enum::session_created)
        throw noheap::runtime_error("Expected session created unit.");
    else if (session_info.status == session_info_type::status_enum::hs3
             && unit.header.type != unit_type::unit_type_enum::session_confirmed)
        throw noheap::runtime_error("Expected session confirmed unit.");
    else if (session_info.status == session_info_type::status_enum::is_connected
             && unit.header.type != unit_type::unit_type_enum::data)
        throw noheap::runtime_error("Expected unit to contain payload data.");
    else
        session_info.status = typename session_info_type::status_enum(
            static_cast<std::size_t>(session_info.status) + 1);
}
noise::buffer_type<sizeof(typename essu::unit_type::header_data_type)>
    essu::protocol_type::derive_header_obfs_key(
        typename noise_context_type::cipher_state &header_cipher_state,
        std::uint32_t                              number) const {
    noise::buffer_type<sizeof(typename essu::unit_type::header_data_type)
                       + noise_context_type::mac_size>
        obfs_key_tmp{};
    header_cipher_state.input_buffer.set({obfs_key_tmp.data(), obfs_key_tmp.size()},
                                         obfs_key_tmp.size()
                                             - noise_context_type::mac_size);
    header_cipher_state.set_encrypt_nonce(number);
    header_cipher_state.encrypt({});

    return noheap::to_buffer<decltype(derive_header_obfs_key(header_cipher_state,
                                                             number))>(obfs_key_tmp);
}

#endif
