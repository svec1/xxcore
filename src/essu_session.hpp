#ifndef ESSU_SESSION_HPP
#define ESSU_SESSION_HPP

#include "essu_protocol.hpp"

using namespace boost;

namespace essu {

template<network::Udp_stream TStream>
class session {
public:
    using udp_stream = TStream;

public:
    session(udp_stream &_stream, udp_stream::address_type _remote_addr,
            noise::noise_role _role, noise::prologue_extention_type _ext,
            const noise::pre_shared_key_type       &_pre_shared_key,
            const noise_context_type::keypair_type &_local_keypair,
            const noise_context_type::dh_key_type  &_remote_public_key);

public:
    // Establishes connection with node(remote_addr): performs noise handshake
    void establish_connection();

    void run_stream_session();

private:
    template<typename... Args>
    void throw_error(std::format_string<Args...> format, Args &&...args);

private:
    template<network::Udp_stream TStream_tmp>
    static void node_send(TStream_tmp &stream, essu::wrapper_packet_type &pckt,
                          const essu::session_info_type &session_info);
    template<network::Udp_stream TStream_tmp>
    static void node_receive(TStream_tmp &stream, essu::wrapper_packet_type &pckt,
                             const session_info_type &session_info);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("ESSU_SESSION");

private:
    static constexpr log_handler log{buffer_owner};

private:
    udp_stream &stream;

    session_info_type info;

    noheap::buffer_chars_type<
        noheap::buffer_size<typename network::buffer_address_v<TStream::v>::type> * 2>
                           buffer_hex_remote_addr;
    const std::string_view hex_remote_addr{buffer_hex_remote_addr};

    std::atomic<bool> running = false;
};
} // namespace essu

template<network::Udp_stream TStream>
essu::session<TStream>::session(udp_stream                             &_stream,
                                udp_stream::address_type                _remote_addr,
                                noise::noise_role                       _role,
                                noise::prologue_extention_type          _ext,
                                const noise::pre_shared_key_type       &_pre_shared_key,
                                const noise_context_type::keypair_type &_local_keypair,
                                const noise_context_type::dh_key_type &_remote_public_key)
    : stream(_stream), info(stream.get_address_bytes(_remote_addr)),
      buffer_hex_remote_addr(
          noheap::clip_buffer<noheap::buffer_size<decltype(buffer_hex_remote_addr)>, 0>(
              noheap::hex_encode(info.addr))) {
    essu::wrapper_packet_type::get_protocol().register_session_info(
        info, _role, _ext, _pre_shared_key, _local_keypair, _remote_public_key);
}
template<network::Udp_stream TStream>
void essu::session<TStream>::establish_connection() {
    essu::wrapper_packet_type pckt{};
    const auto               &protocol = pckt.get_protocol();

    // Establishes connection
    try {
        // Performs noise handshake
        protocol.start_handshake(info);
        while (true) {
            auto action = protocol.get_handshake_action(info);
            if (action == noise::noise_action::WRITE_MESSAGE)
                node_send(stream, pckt, info);
            else if (action == noise::noise_action::READ_MESSAGE)
                node_receive(stream, pckt, info);
            else
                break;
        }

        protocol.stop_handshake(info);
    } catch (noheap::runtime_error &excp) {
        this->throw_error("Failed to establish connection. {}", excp.what());
    }
}

template<network::Udp_stream TStream>
void essu::session<TStream>::run_stream_session() {
    const auto &protocol = essu::wrapper_packet_type::get_protocol();

    running.store(true);

    try {
        while (true) {
            future_wrapper future_object_to_send([&]() {
                try {
                    essu::wrapper_packet_type pckt{};

                    while (running.load()
                           && pckt.get_protocol().needs_to_rehandshake(info))
                        node_send(stream, pckt, info);
                } catch (...) {
                    running.store(false);
                    throw;
                }
            });
            future_wrapper future_object_to_receive([&]() {
                try {
                    essu::wrapper_packet_type pckt{};

                    while (running.load()
                           && pckt.get_protocol().needs_to_rehandshake(info))
                        node_receive(stream, pckt, info);
                } catch (...) {
                    running.store(false);
                    throw;
                }
            });

            future_object_to_send.get();
            future_object_to_receive.get();

            establish_connection();
        }
    } catch (noheap::runtime_error &excp) {
        this->throw_error("Connection terminated. {}", excp.what());
    }
}

template<network::Udp_stream TStream>
template<typename... Args>
void essu::session<TStream>::throw_error(std::format_string<Args...> format,
                                         Args &&...args) {
    noheap::buffer_chars_type<noheap::runtime_error::buffer_size
                              - noheap::buffer_size<decltype(buffer_owner)>
                              - noheap::buffer_size<decltype(buffer_hex_remote_addr)>>
        buffer_format{};
    std::format_to_n(buffer_format.begin(), buffer_format.size(), format,
                     std::forward<Args>(args)...);
    throw noheap::runtime_error(buffer_owner, "{}: {}", hex_remote_addr,
                                std::string_view(buffer_format));
}

template<network::Udp_stream TStream>
template<network::Udp_stream TStream_tmp>
void essu::session<TStream>::node_send(TStream_tmp               &stream,
                                       essu::wrapper_packet_type &pckt,
                                       const session_info_type   &session_info) {
    stream.template send_to<decltype(pckt)>(
        pckt, TStream::get_address_object(session_info.addr));
}

template<network::Udp_stream TStream>
template<network::Udp_stream TStream_tmp>
void essu::session<TStream>::node_receive(TStream_tmp               &stream,
                                          essu::wrapper_packet_type &pckt,
                                          const session_info_type   &session_info) {
    try {
        stream
            .template async_receive_from<decltype(pckt)>(
                pckt, TStream::get_address_object(session_info.addr))
            .validate();
    } catch (system::system_error &excp) {
        if (excp.code().value() != asio::error::operation_aborted)
            throw;
        throw noheap::runtime_error(buffer_owner, "Timeout has been reached.");
    }
}

#endif
