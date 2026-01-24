#ifndef ALSA_UDP_VOICE_SERVICE_HPP
#define ALSA_UDP_VOICE_SERVICE_HPP

#include "crypt.hpp"
#include "net.hpp"
#include "stream_audio.hpp"

using namespace boost;

template<std::size_t _max_stream_size, std::size_t _min_count_blocks_for_nonwaiting>
struct voice_extention {
    static constexpr std::size_t max_stream_size = _max_stream_size;
    static constexpr std::size_t min_count_blocks_for_nonwaiting =
        _min_count_blocks_for_nonwaiting;

public:
    struct packet_t : public packet_native_t<stream_audio::encode_buffer_size> {
        static constexpr std::size_t uuid_size = 32;
        using uuid_type                        = openssl_context::buffer_type<uuid_size>;

        uuid_type uuid;
        size_t    sequence_number = 0;
    };
    struct protocol_t : public protocol_native_t<packet_t, noheap::log_impl::create_owner(
                                                               "VOICE_PROTOCOL")> {
    public:
        constexpr void prepare(packet_t                      &pckt,
                               protocol_t::callback_prepare_t callback) const override {
            static openssl_context                    ossl_ctx;
            static const typename packet_t::uuid_type uuid{
                ossl_ctx.get_random_bytes<packet_t::uuid_size>()};

            callback(pckt);

            pckt.uuid            = uuid;
            pckt.sequence_number = local_sequence_number++;
        }
        constexpr void handle(packet_t                     &pckt,
                              protocol_t::callback_handle_t callback) const override {
            jitter_buffer.push_back(std::move(pckt));

            if (jitter_buffer.size() == max_stream_size)
                filled = true;

            if (filled)
                callback(jitter_buffer.pop_front());
        }

    private:
        mutable noheap::monotonic_array<packet_t, max_stream_size> jitter_buffer;

        mutable std::size_t local_sequence_number = 0;
        mutable bool        filled                = false;
    };

public:
    using packet = packet<packet_t, protocol_t>;

public:
    struct action : public ::action<packet> {
        using packet = ::action<packet>::packet;

    public:
        action() : running(true), pushed(false), filled(0) {
            in_stream  = std::async(std::launch::async, [this] {
                try {
                    while (running.load()) {
                        typename stream_audio::encode_buffer_type buffer_tmp =
                            io_audio.read();
                        {
                            std::lock_guard lock(in_stream_m);
                            in_stream_buffer.push(buffer_tmp);
                        }
                        filled.fetch_add(1);
                        filled.notify_one();
                    }
                } catch (...) {
                    running.store(false);
                    throw;
                }
            });
            out_stream = std::async(std::launch::async, [this] {
                try {
                    if (!pushed.load())
                        pushed.wait(false);

                    while (running.load()) {
                        typename packet::packet_type::buffer_type buffer_tmp;
                        {
                            std::lock_guard lock(out_stream_m);
                            buffer_tmp = out_stream_buffer.pop();
                        }
                        io_audio.write(buffer_tmp, false);
                    }
                } catch (...) {
                    running.store(false);
                    throw;
                }
            });
        }
        ~action() {
            running.store(false);
            wait_stopping();
        }

    private:
        void check_running() {
            if (running.load())
                return;

            wait_stopping();
        }

        void wait_stopping() {
            if (in_stream.valid())
                in_stream.get();
            if (out_stream.valid())
                out_stream.get();
        }

    public:
        constexpr void init_packet(packet::packet_t &pckt) override {
            check_running();

            if (!filled.load())
                filled.wait(0);
            filled.fetch_sub(1);

            std::lock_guard lock(in_stream_m);
            pckt.buffer = in_stream_buffer.pop();
        }
        constexpr void process_packet(packet::packet_t &&pckt) override {
            check_running();

            std::lock_guard lock(out_stream_m);
            out_stream_buffer.push(pckt.buffer);

            noheap::println("{}", out_stream_buffer.size());

            if (!pushed.load()
                && out_stream_buffer.size()
                       == stream_audio::default_base_audio::cfg
                                  .diviser_for_hardware_buffer
                              + 1) {
                pushed.store(true);
                pushed.notify_one();
            }
        }

    private:
        std::mutex               in_stream_m, out_stream_m;
        std::future<void>        in_stream, out_stream;
        std::atomic<bool>        running, pushed;
        std::atomic<std::size_t> filled;

        stream_audio io_audio;

        noheap::ring_buffer<typename packet::buffer_type, max_stream_size>
            in_stream_buffer, out_stream_buffer;
    };
};

class unix_udp_voice_service {
public:
    static constexpr ipv v = ipv::v4;

    using voice_extention_d = voice_extention<64, 32>;
    using udp_stream_t      = net_stream_udp<typename voice_extention_d::action, v>;
    using packet            = voice_extention_d::packet;
    using ipv_t             = udp_stream_t::ipv_t;

public:
    unix_udp_voice_service(asio::ip::port_type port);

public:
    void run(const ipv_t &addr);

private:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("UUV_SERVICE");
    static constexpr log_handler log{buffer_owner};

private:
    asio::io_context io;
    udp_stream_t     udp_stream;
};

unix_udp_voice_service::unix_udp_voice_service(asio::ip::port_type port)
    : udp_stream(io, port) {
}
void unix_udp_voice_service::run(const ipv_t &addr) {
    try {
        thread_local packet pckt_for_receiving, pckt_for_sending;

        udp_stream.register_send_handler<0>(pckt_for_sending, addr);
        udp_stream.register_receive_handler(pckt_for_receiving);

        io.run();

    } catch (noheap::runtime_error &excp) {
        if (!excp.has_setting_owner())
            excp.set_owner(buffer_owner);
        throw;
    }
}

#endif
