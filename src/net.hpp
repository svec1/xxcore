#ifndef NET_HPP
#define NET_HPP

#include <boost/asio.hpp>

#include "utils.hpp"

using namespace boost;

enum class ipv { v4 = 0, v6 };

static constexpr ipv IPV4 = ipv::v4;
static constexpr ipv IPV6 = ipv::v6;

template <std::size_t _buffer_size, std::size_t _max_count_addrs>
struct packet_native_t {
  public:
    static constexpr std::size_t buffer_size = _buffer_size;
    static constexpr std::size_t max_count_addrs = _max_count_addrs;

    using buffer_t = noheap::buffer_bytes_t<buffer_size>;

  public:
    packet_native_t() = default;

    virtual buffer_t::value_type *get_buffer() {
        return reinterpret_cast<buffer_t::value_type *>(this) + 8;
    }

  public:
    buffer_t buffer{};
};

template <typename T>
concept Derived_from_packet_native_t =
    std::derived_from<T, packet_native_t<T::buffer_size, T::max_count_addrs>>;

template <Derived_from_packet_native_t T,
          noheap::log_impl::owner_impl::buffer_t _buffer_owner =
              noheap::log_impl::create_owner("PROTOCOL")>
struct protocol_native_t {
  public:
    using packet_t = T;
    using callback_func_t = std::function<void(T &&)>;

  public:
    constexpr virtual void prepare(T &pckt) const {}
    constexpr virtual void handle(T &pckt, callback_func_t callback) const {}

  public:
    static constexpr noheap::log_impl::owner_impl::buffer_t buffer_owner =
        _buffer_owner;

  protected:
    static constexpr log_handler log{buffer_owner};
};

template <typename T>
concept Derived_from_protocol_native_t =
    std::derived_from<T,
                      protocol_native_t<typename T::packet_t, T::buffer_owner>>;

template <std::size_t _buffer_size, std::size_t _max_count_addrs>
struct debug_extention {
    struct packet_t : public packet_native_t<_buffer_size, _max_count_addrs> {
        std::size_t mark_time;
    };

    struct protocol_t
        : public protocol_native_t<packet_t, noheap::log_impl::create_owner(
                                                 "DEBUG_PROTOCOL")> {
        constexpr void prepare(packet_t &pckt) const override {
            pckt.mark_time = get_now_ms();
        }
        constexpr void
        handle(packet_t &pckt,
               protocol_t::callback_func_t callback) const override {
            static unsigned long long count_accepted = 0;
            static unsigned long long during = get_now_ms();

            unsigned long long now = get_now_ms();

            ++count_accepted;
            if (now - during > 1000) {
                this->log.template to_all<log_handler::output_type::async>(
                    "Was recieved last packet {} "
                    "ms({} packet/s.)",
                    now - pckt.mark_time, count_accepted);
                during = now;
                count_accepted = 0;
            }
            this->pckt = pckt;
        }
        constexpr virtual packet_t get_packet() const { return pckt; }

      private:
        mutable packet_t pckt;
    };
};

template <Derived_from_packet_native_t TPacket_internal,
          Derived_from_protocol_native_t TProtocol =
              protocol_native_t<TPacket_internal>>
class packet final : public TPacket_internal {
  public:
    using packet_t = TPacket_internal;
    using protocol_t = TProtocol;

  public:
    static constexpr std::size_t size = sizeof(packet_t) - 8;

  public:
    packet() = default;
    packet(packet_t &&pckg) : packet_t(pckg) {}

  public:
    static constexpr void prepare(packet_t &pckt) { aprt.prepare(pckt); }
    static constexpr void handle(packet_t &pckt,
                                 protocol_t::callback_func_t callback) {
        aprt.handle(pckt, callback);
    }

  private:
    static constexpr protocol_t aprt{};
};

template <typename T>
concept Packet =
    std::same_as<T, packet<typename T::packet_t, typename T::protocol_t>>;

template <Packet TPacket> struct action {
  public:
    using packet = TPacket;

  public:
    constexpr action() = default;

  public:
    constexpr virtual void init_buffer(packet::buffer_t &buffer) const = 0;
    constexpr virtual void process_packet(packet &&pckt) const = 0;
};

template <typename T>
concept Derived_from_action = std::derived_from<T, action<typename T::packet>>;

template <std::size_t _buffer_size, std::size_t _max_count_addrs>
using debug_packet = packet<
    typename debug_extention<_buffer_size, _max_count_addrs>::packet_t,
    typename debug_extention<_buffer_size, _max_count_addrs>::protocol_t>;

template <ipv v = ipv::v4,
          typename _ipv_t = std::conditional_t<
              static_cast<bool>(v), asio::ip::address_v6, asio::ip::address_v4>>
class nstream final {
    static constexpr asio::ip::udp udp() {
        if constexpr (v == ipv::v6)
            return asio::ip::udp::v6();
        else
            return asio::ip::udp::v4();
    }

  public:
    using ipv_t = _ipv_t;

  public:
    nstream(asio::io_context &io, asio::ip::port_type _port);

  public:
    template <Derived_from_action Action, Packet TPacket>
        requires std::is_same_v<typename decltype(Action{})::packet, TPacket>
    void send_to(
        TPacket &pckt,
        const noheap::monotonic_array<ipv_t, TPacket::max_count_addrs> &addrs);
    template <Derived_from_action Action, Packet TPacket>
        requires std::is_same_v<typename decltype(Action{})::packet, TPacket>
    void receive_from(TPacket &pckt);

  private:
    static constexpr noheap::log_impl::owner_impl::buffer_t buffer_owner =
        noheap::log_impl::create_owner("NSTREAM");
    static constexpr log_handler log{buffer_owner};

  private:
    asio::ip::udp::socket sock;
    asio::ip::port_type port;
};

template <ipv v, typename _ipv_t>
nstream<v, _ipv_t>::nstream(asio::io_context &io, asio::ip::port_type _port)
    : sock(io), port(_port) {
    static thread_local boost::system::error_code ec;

    sock.open(udp(), ec);
    if (ec.value())
        throw noheap::runtime_error(
            buffer_owner, "Failed to open udp socket: {}.", ec.message());

    sock.bind({udp(), port}, ec);
    if (ec.value())
        throw noheap::runtime_error(
            buffer_owner, "Failed to bind udp socket: {}.", ec.message());

    sock.set_option(asio::socket_base::reuse_address(true));
}
template <ipv v, typename _ipv_t>
template <Derived_from_action Action, Packet TPacket>
    requires std::is_same_v<typename decltype(Action{})::packet, TPacket>
void nstream<v, _ipv_t>::send_to(
    TPacket &pckt,
    const noheap::monotonic_array<ipv_t, TPacket::max_count_addrs> &addrs) {
    static constexpr Action act;

    thread_local std::size_t it = 0;
    thread_local const auto handle_send =
        [this, &pckt, &addrs](const system::error_code &ec, std::size_t size) {
            if (ec.value())
                throw noheap::runtime_error(
                    buffer_owner, "Failed to send packet: {}.", ec.message());
            else if (size != TPacket::size)
                throw noheap::runtime_error(
                    buffer_owner, "An incomplete package was sent: {} bytes.",
                    size);

            ++it;
            send_to<Action>(pckt, addrs);
        };

    if (it != addrs.size() && it != 0)
        return;
    it = 0;

    act.init_buffer(pckt.buffer);
    TPacket::prepare(pckt);
    std::for_each(addrs.begin(), addrs.end(), [this, &pckt](const auto &addr) {
        sock.async_send_to(asio::buffer(pckt.get_buffer(), TPacket::size),
                           asio::ip::udp::endpoint{addr, port}, handle_send);
    });
}

template <ipv v, typename _ipv_t>
template <Derived_from_action Action, Packet TPacket>
    requires std::is_same_v<typename decltype(Action{})::packet, TPacket>
void nstream<v, _ipv_t>::receive_from(TPacket &pckt) {
    static constexpr Action act;

    thread_local asio::ip::udp::endpoint sender_endpoint;
    thread_local const auto handle_receive =
        [this, &pckt](const system::error_code &ec, std::size_t size) {
            if (ec.value())
                throw noheap::runtime_error(buffer_owner,
                                            "Failed to receive packet: {}.",
                                            ec.message());
            else if (size != TPacket::size)
                noheap::runtime_error(
                    buffer_owner,
                    "An incomplete package was receive: {} bytes.", size);

            TPacket::handle(pckt, std::bind(&Action::process_packet, act,
                                            std::placeholders::_1));
            receive_from<Action>(pckt);
        };

    sock.async_receive_from(
        boost::asio::buffer(pckt.get_buffer(), TPacket::size), sender_endpoint,
        handle_receive);
}

#endif
