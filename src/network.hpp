#ifndef NET_HPP
#define NET_HPP

#include <boost/asio.hpp>

#include "utils.hpp"

namespace network {

using namespace boost;

enum class ipv { v4 = 0, v6 };

static constexpr ipv         IPV4                 = ipv::v4;
static constexpr ipv         IPV6                 = ipv::v6;
static constexpr std::size_t max_count_addresses  = 4;
static constexpr std::size_t max_buffered_packets = 16;

static constexpr std::size_t max_buffer_address_size =
    asio::ip::address_v6::bytes_type{}.size();

using buffer_address_type = asio::ip::address_v6::bytes_type;

using buffer_address_v4_type = noheap::buffer_type<buffer_address_type::value_type, 4>;
using buffer_address_v6_type = noheap::buffer_type<buffer_address_type::value_type, 8>;

template<ipv v>
struct buffer_address_v {
private:
    static consteval auto get_buffer_address_type() {
        if constexpr (v == ipv::v4)
            return buffer_address_v4_type{};
        else
            return buffer_address_v6_type{};
    }

public:
    using type = decltype(get_buffer_address_type());
};

template<typename T>
struct packet_native_type;
template<typename T>
concept Packet_native_t =
    std::same_as<std::decay_t<T>,
                 packet_native_type<typename std::decay_t<T>::extention_data_type>>;

template<Packet_native_t T, noheap::log_impl::owner_impl::buffer_type _buffer_owner>
struct protocol_native_type;
template<typename T>
concept Derived_from_protocol_native_t =
    std::derived_from<std::decay_t<T>,
                      protocol_native_type<typename std::decay_t<T>::packet_type,
                                           std::decay_t<T>::buffer_owner>>;

template<Packet_native_t TPacket>
struct action;
template<Packet_native_t TPacket>
struct decoy_action;
template<typename T>
concept Derived_from_action =
    std::derived_from<std::decay_t<T>, action<typename std::decay_t<T>::packet_type>>;

template<typename T>
struct packet_native_type {
public:
    using extention_data_type = T;
    using represent_type      = noheap::rbyte;

public:
    packet_native_type() = default;

public:
    packet_native_type(const packet_native_type &packet) { *this = packet; }
    packet_native_type(packet_native_type &&packet) { *this = std::move(packet); }
    packet_native_type &operator=(const packet_native_type &packet) {
        this->_extention_data = packet._extention_data;
        return *this;
    }
    packet_native_type &operator=(packet_native_type &&packet) {
        this->_extention_data = std::move(packet._extention_data);
        return *this;
    }

public:
    extention_data_type       *operator->() noexcept { return _extention_data_p; }
    const extention_data_type *operator->() const noexcept { return _extention_data_p; }

public:
    constexpr std::size_t size() const noexcept { return sizeof(extention_data_type); }

public:
    represent_type *data() noexcept { return reinterpret_cast<represent_type *>(this); }

private:
    extention_data_type        _extention_data;
    extention_data_type *const _extention_data_p = &_extention_data;
};

template<Packet_native_t TPacket>
struct action {
public:
    using packet_type         = TPacket;
    using init_packet_type    = std::function<void(packet_type &)>;
    using process_packet_type = std::function<void(packet_type &&)>;

public:
    action() = default;

public:
    constexpr virtual void init_packet(packet_type &pckt)     = 0;
    constexpr virtual void process_packet(packet_type &&pckt) = 0;
};

template<Packet_native_t TPacket>
struct decoy_action : public action<TPacket> {
    using packet_type = decoy_action::packet_type;

public:
    constexpr void init_packet(packet_type &pckt) override {}
    constexpr void process_packet(packet_type &&pckt) override {}
};

template<Packet_native_t T, noheap::log_impl::owner_impl::buffer_type _buffer_owner>
struct protocol_native_type {
public:
    using packet_type           = T;
    using action_type           = action<packet_type>;
    using callback_prepare_type = action_type::init_packet_type;
    using callback_handle_type  = action_type::process_packet_type;

    static constexpr std::size_t timeout_ms = 5000;

public:
    constexpr virtual void prepare(packet_type &pckt, buffer_address_type addr,
                                   callback_prepare_type callback) const {}
    constexpr virtual void handle(packet_type &pckt, buffer_address_type addr,
                                  callback_handle_type callback) const {}

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        _buffer_owner;

protected:
    static constexpr log_handler log{buffer_owner};
};

struct debug_extention {
    struct extention_data_type {
        std::size_t mark_time;
    };

public:
    using packet_type = packet_native_type<extention_data_type>;

    struct protocol_type
        : public protocol_native_type<packet_type,
                                      noheap::log_impl::create_owner("DEBUG_PROTOCOL")> {
        constexpr void prepare(packet_type &pckt, buffer_address_type addr,
                               callback_prepare_type callback) const override {
            callback(pckt);

            pckt->mark_time = get_now_ms();
        }
        constexpr void handle(packet_type &pckt, buffer_address_type addr,
                              callback_handle_type callback) const override {
            static std::size_t count_accepted = 0;
            static std::size_t during         = get_now_ms();

            std::size_t now = get_now_ms();

            ++count_accepted;
            if (now - during > 1000) {
                this->log.template to_all<log_handler::output_type::async>(
                    "Was recieved last packet {} "
                    "ms({} packet/s.)",
                    now - pckt->mark_time, count_accepted);
                during         = now;
                count_accepted = 0;
            }

            callback(std::move(pckt));
        }
    };
};

template<Packet_native_t TPacket_internal, Derived_from_protocol_native_t TProtocol>
    requires std::same_as<TPacket_internal, typename TProtocol::packet_type>
class wrapper_packet final : public TPacket_internal {
public:
    using packet_type   = TPacket_internal;
    using protocol_type = TProtocol;

public:
    wrapper_packet() = default;
    wrapper_packet(packet_type &&pckt) : packet_type(pckt) {}

public:
    static constexpr void prepare(packet_type &pckt, buffer_address_type addr,
                                  protocol_type::callback_prepare_type callback) {
        prt.prepare(pckt, addr, callback);
    }
    static constexpr void handle(packet_type &&pckt, buffer_address_type addr,
                                 protocol_type::callback_handle_type callback) {
        prt.handle(pckt, addr, callback);
    }

public:
    static constexpr const protocol_type &get_protocol() { return prt; }

private:
    static constexpr protocol_type prt{};
};

template<typename T>
concept Wrapper_packet =
    std::same_as<std::decay_t<T>,
                 wrapper_packet<typename std::decay_t<T>::packet_type,
                                typename std::decay_t<T>::protocol_type>>;
template<typename TPacket, typename TAction>
concept Compatible_wrapper_packet_with_action =
    Wrapper_packet<TPacket> && Derived_from_action<TAction>
    && std::same_as<typename std::decay_t<TAction>::packet_type,
                    typename std::decay_t<TPacket>::packet_type>;

using debug_packet = wrapper_packet<typename debug_extention::packet_type,
                                    typename debug_extention::protocol_type>;

template<Derived_from_action Action, ipv _v>
class net_stream_udp;

template<typename T>
concept Net_stream_udp = std::same_as<T, net_stream_udp<typename T::action_type, T::v>>;

template<Derived_from_action Action, ipv _v>
class net_stream_udp {
private:
    static constexpr asio::ip::udp get_ipv() {
        if constexpr (v == ipv::v6)
            return decltype(get_ipv())::v6();
        else
            return decltype(get_ipv())::v4();
    }

public:
    static constexpr ipv v = _v;

public:
    using basic_socket_type = asio::ip::udp;
    using socket_type       = basic_socket_type::socket;
    using action_type       = Action;
    using endpoint_type     = basic_socket_type::endpoint;
    using address_type = std::conditional_t<static_cast<bool>(v), asio::ip::address_v6,
                                            asio::ip::address_v4>;
    using port_type    = asio::ip::port_type;

    enum class async_socket_operation {
        send_to = 0,
        receive_from,
        timer,
    };

public:
    net_stream_udp(net_stream_udp &&)                 = default;
    net_stream_udp(const net_stream_udp &)            = delete;
    net_stream_udp &operator=(const net_stream_udp &) = delete;

    net_stream_udp();
    net_stream_udp(asio::ip::port_type _port);

    template<typename TOther>
    net_stream_udp(TOther &&stream);
    template<typename TOther>
    net_stream_udp &operator=(TOther &&stream);

    ~net_stream_udp();

public:
    void open(port_type _port);
    void close();

public:
    bool is_open() const { return socket.is_open(); }

    Action   &get_action() { return act; }
    port_type get_port() const { return port; }
    bool      get_running() const { return running; }
    void      set_running(bool _running) { running = _running; }

    void        cancel();
    std::size_t run();

public:
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    void send_to(TWrapper_packet &pckt, address_type addr);
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    void receive_from(TWrapper_packet &pckt);

    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    void async_send_to(TWrapper_packet &pckt, address_type addr);
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    void async_receive_from(TWrapper_packet &pckt, address_type addr);

private:
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    void detail_async_receive_from(TWrapper_packet &pckt, address_type addr,
                                   bool buffered_packets_is_null);

    template<async_socket_operation async_op, std::size_t delay, typename Func,
             typename TBuffer>
    void register_async_socket_operation(Func &&func, TBuffer &&buffer,
                                         endpoint_type &endpoint);

public:
    static buffer_address_type get_address_bytes(address_type addr);
    static address_type        get_address_object(buffer_address_type addr);
    static address_type        get_address_object(asio::ip::address addr);

private:
    static void init_socket(net_stream_udp<Action, v> &stream, port_type port);
    static void handle_error(const system::error_code &ec);

private:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("NSTREAM");
    static constexpr log_handler log{buffer_owner};

private:
    asio::io_context io;
    socket_type      socket;
    Action           act;

    port_type port;
    bool      running;
};

template<Derived_from_action Action, ipv v>
net_stream_udp<Action, v>::net_stream_udp(port_type _port)
    : port(_port), running(true), socket(io) {
    init_socket(*this, port);
}

template<Derived_from_action Action, ipv v>
template<typename TOther>
net_stream_udp<Action, v>::net_stream_udp(TOther &&stream)
    : io(stream.io), port(stream.port), running(stream.running), socket(stream.socket) {
}
template<Derived_from_action Action, ipv v>
net_stream_udp<Action, v>::~net_stream_udp() {
    this->close();
}

template<Derived_from_action Action, ipv v>
template<typename TOther>
net_stream_udp<Action, v> &net_stream_udp<Action, v>::operator=(TOther &&stream) {
    port    = std::move(port);
    running = std::move(running);
    socket  = std::move(socket);
    return *this;
}

template<Derived_from_action Action, ipv v>
void net_stream_udp<Action, v>::open(port_type _port) {
    if (socket.is_open())
        socket.close();

    port = _port;

    init_socket(*this, port);
}
template<Derived_from_action Action, ipv v>
void net_stream_udp<Action, v>::close() {
    socket.close();
}

template<Derived_from_action Action, ipv v>
void net_stream_udp<Action, v>::cancel() {
    socket.cancel();
}
template<Derived_from_action Action, ipv v>
std::size_t net_stream_udp<Action, v>::run() {
    return io.run();
}

template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
void net_stream_udp<Action, v>::send_to(TWrapper_packet &pckt, address_type addr) {
    if (!running)
        return;

    system::error_code ec;

    std::decay_t<TWrapper_packet>::prepare(
        pckt, this->get_address_bytes(addr),
        std::bind(&Action::init_packet, &this->act, std::placeholders::_1));
    socket.send_to(asio::const_buffer(pckt.data(), pckt.size()), {addr, this->port}, 0,
                   ec);

    this->handle_error(ec);
}
template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
void net_stream_udp<Action, v>::receive_from(TWrapper_packet &pckt) {
    if (!running)
        return;

    system::error_code      ec;
    asio::ip::udp::endpoint sender_endpoint;

    socket.receive_from(asio::mutable_buffer(pckt.data(), pckt.size()), sender_endpoint,
                        0, ec);

    this->handle_error(ec);

    std::decay_t<TWrapper_packet>::handle(
        std::move(pckt), this->get_address_bytes(sender_endpoint.address()),
        std::bind(&Action::process_packet, &this->act, std::placeholders::_1));
}

template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
void net_stream_udp<Action, v>::async_send_to(TWrapper_packet &pckt, address_type addr) {
    thread_local asio::ip::udp::endpoint receiver_endpoint;

    receiver_endpoint = {addr, this->port};
    std::decay_t<TWrapper_packet>::prepare(
        pckt, this->get_address_bytes(receiver_endpoint.address()),
        std::bind(&Action::init_packet, &this->act, std::placeholders::_1));

    this->template register_async_socket_operation<async_socket_operation::send_to, 0>(
        []() {}, asio::const_buffer{pckt.data(), pckt.size()}, receiver_endpoint);
}

template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
void net_stream_udp<Action, v>::async_receive_from(TWrapper_packet &pckt,
                                                   address_type     addr) {
    detail_async_receive_from(pckt, addr, false);
}
template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
void net_stream_udp<Action, v>::detail_async_receive_from(TWrapper_packet &pckt,
                                                          address_type     addr,
                                                          bool buffered_packets_is_null) {
    using packet_type          = typename std::decay_t<TWrapper_packet>::packet_type;
    using buffered_packet_type = struct {
        packet_type pckt;
        std::size_t accepted_ms;
    };

    static std::mutex m;
    static noheap::monotonic_array<
        std::pair<address_type,
                  noheap::ring_buffer<buffered_packet_type, max_buffered_packets>>,
        max_count_addresses>
        buffer_packets;

    thread_local asio::ip::udp::endpoint sender_endpoint;

    const auto handle_receive = [this](TWrapper_packet &pckt, address_type addr) {
        if (const auto &remote_addr = this->get_address_object(sender_endpoint.address());
            remote_addr != addr) {
            std::lock_guard<std::mutex> lock(m);
            if (const auto &it = std::find_if(
                    buffer_packets.begin(), buffer_packets.end(),
                    [&remote_addr](const auto &it) { return it.first == remote_addr; });
                it != buffer_packets.end())
                it->second.push(buffered_packet_type{*dynamic_cast<packet_type *>(&pckt),
                                                     get_now_ms()});
            else if (buffer_packets.size() < max_count_addresses)
                buffer_packets.push_back(typename decltype(buffer_packets)::value_type{
                    remote_addr,
                    {buffered_packet_type{*dynamic_cast<packet_type *>(&pckt),
                                          get_now_ms()}}});

            this->detail_async_receive_from(pckt, addr, true);
        }

        std::decay_t<TWrapper_packet>::handle(
            std::move(pckt), this->get_address_bytes(addr),
            std::bind(&Action::process_packet, &this->act, std::placeholders::_1));
    };

    if (!buffered_packets_is_null) {
        std::lock_guard<std::mutex> lock(m);
        if (const auto &it =
                std::find_if(buffer_packets.begin(), buffer_packets.end(),
                             [&addr](const auto &it) { return it.first == addr; });
            it != buffer_packets.end() && it->second.size() < max_buffered_packets) {
            while (it->second.size()) {
                auto buffered_packet = it->second.pop();

                if (get_now_ms() - buffered_packet.accepted_ms
                    >= std::decay_t<TWrapper_packet>::protocol_type::timeout_ms)
                    continue;

                pckt = std::move(buffered_packet.pckt);
                return;
            }
        }
    }

    this->template register_async_socket_operation<async_socket_operation::receive_from,
                                                   0>(
        std::bind(handle_receive, std::ref(pckt), addr),
        asio::mutable_buffer{pckt.data(), pckt.size()}, sender_endpoint);
}

template<Derived_from_action Action, ipv v>
template<net_stream_udp<Action, v>::async_socket_operation async_op, std::size_t delay,
         typename Func, typename TBuffer>
void net_stream_udp<Action, v>::register_async_socket_operation(Func         &&func,
                                                                TBuffer      &&buffer,
                                                                endpoint_type &endpoint) {
    if (!running)
        return;

    const auto handler = std::bind(
        [func](const system::error_code &ec) {
            handle_error(ec);
            func();
        },
        asio::placeholders::error);

    if constexpr (async_op == async_socket_operation::send_to)
        socket.async_send_to(std::forward<TBuffer>(buffer), endpoint, handler);
    else if constexpr (async_op == async_socket_operation::receive_from) {
        socket.async_receive_from(std::forward<TBuffer>(buffer), endpoint, handler);
    } else
        static_assert(false, "Unknown async operation.");
}

template<Derived_from_action Action, ipv v>
buffer_address_type net_stream_udp<Action, v>::get_address_bytes(address_type addr) {
    return noheap::to_new_buffer<buffer_address_type>(addr.to_bytes());
}
template<Derived_from_action Action, ipv v>
net_stream_udp<Action, v>::address_type
    net_stream_udp<Action, v>::get_address_object(buffer_address_type addr) {
    return address_type(noheap::to_new_buffer<decltype(address_type{}.to_bytes())>(addr));
}
template<Derived_from_action Action, ipv v>
net_stream_udp<Action, v>::address_type
    net_stream_udp<Action, v>::get_address_object(asio::ip::address addr) {
    if constexpr (std::same_as<address_type, asio::ip::address_v4>)
        return addr.to_v4();
    else
        return addr.to_v6();
}

template<Derived_from_action Action, ipv v>
void net_stream_udp<Action, v>::init_socket(net_stream_udp<Action, v> &stream,
                                            port_type                  port) {
    system::error_code ec;

    stream.socket.close();
    stream.socket.open(get_ipv(), ec);
    if (ec.value())
        handle_error(ec);

    stream.socket.set_option(typename socket_type::reuse_address(true));
    stream.socket.set_option(typename socket_type::broadcast(false));

    stream.socket.bind({get_ipv(), port}, ec);
    if (ec.value() && ec != asio::error::address_in_use)
        handle_error(ec);
}
template<Derived_from_action Action, ipv v>
void net_stream_udp<Action, v>::handle_error(const system::error_code &ec) {
    if (!ec.value())
        return;

    throw noheap::runtime_error(buffer_owner, "Network error: {}", ec.message());
}

} // namespace network

#endif
