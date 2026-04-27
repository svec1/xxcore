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
    void register_connection();
    void wait();
    void terminate();

private:
    template<typename... Args>
    void throw_error(std::format_string<Args...> format, Args &&...args);

private:
    void send(const essu::session_info_type &session_info);
    void receive(const session_info_type &session_info);

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("ESSU_SESSION");

private:
    static constexpr log_handler log{buffer_owner};

private:
    udp_stream       &stream;
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
    try {
        decltype(auto) protocol = essu::wrapper_packet_type::get_protocol();
        // Performs noise handshake
        protocol.start_handshake(info);
        while (true) {
            auto action = protocol.get_handshake_action(info);
            if (action == noise::noise_action::WRITE_MESSAGE)
                send(info);
            else if (action == noise::noise_action::READ_MESSAGE)
                receive(info);
            else
                break;
        }

        protocol.stop_handshake(info);
    } catch (noheap::runtime_error &excp) {
        this->throw_error("Failed to establish connection [{}]", excp.what());
    }
}

template<network::Udp_stream TStream>
void essu::session<TStream>::register_connection() {
    running.store(true);
    asio::post(stream.get_executor(), [this] {
        std::optional<noheap::runtime_error> excp;
        try {
            decltype(auto) protocol = essu::wrapper_packet_type::get_protocol();
            while (running.load()) {
                std::atomic<bool> io_running = true;

                future_wrapper future_async_send([this, &io_running]() {
                    try {
                        while (io_running.load() && this->running.load()
                               && !protocol.needs_to_rehandshake(info))
                            this->send(info);
                    } catch (...) {
                        io_running.store(false);
                        throw;
                    }
                });
                future_wrapper future_async_receive([this, &io_running]() {
                    try {
                        while (io_running.load() && this->running.load()
                               && !protocol.needs_to_rehandshake(info))
                            receive(info);
                    } catch (...) {
                        io_running.store(false);
                        throw;
                    }
                });

                future_async_send.get();
                future_async_receive.get();

                // Sends a retry packet to signal the responder to rehandshake
                if (protocol.needs_to_rehandshake(info)
                    && protocol.get_role(info) == noise::noise_role::INITIATOR)
                    send(info);

                establish_connection();
            }
        } catch (noheap::runtime_error &_excp) {
            excp = _excp;
        }

        running.store(false);
        running.notify_all();
        if (excp)
            this->throw_error("Connection terminated [{}]", excp->what());
        this->throw_error("Connection terminated.");
    });
}
template<network::Udp_stream TStream>
void essu::session<TStream>::wait() {
    running.wait(true);
}
template<network::Udp_stream TStream>
void essu::session<TStream>::terminate() {
    running.store(false);
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
void essu::session<TStream>::send(const session_info_type &session_info) {
    stream.template send_to<essu::wrapper_packet_type>(
        TStream::get_address_object(session_info.addr));
}

template<network::Udp_stream TStream>
void essu::session<TStream>::receive(const session_info_type &session_info) {
    if (!stream.template receive_from<essu::wrapper_packet_type>(
            TStream::get_address_object(session_info.addr)))
        throw noheap::runtime_error("Timeout has been reached.");
}

#endif
