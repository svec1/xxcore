#ifndef NET_HPP
#define NET_HPP

#include <boost/asio.hpp>

#include "utils.hpp"

namespace network {

using namespace boost;

enum class ipv { v4 = 0, v6 };

constexpr std::size_t max_count_addresses     = 4;
constexpr std::size_t max_buffered_packets    = 16;
constexpr std::size_t max_packet_size         = 2048;
constexpr std::size_t timeout_ms              = 2500;
constexpr std::size_t max_buffer_address_size = asio::ip::address_v6::bytes_type{}.size();

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
    static constexpr std::size_t size() noexcept { return sizeof(extention_data_type); }

public:
    template<typename TSelf>
    decltype(auto) data(this TSelf &&self) noexcept {
        if constexpr (std::is_const_v<std::remove_reference_t<TSelf>>)
            return reinterpret_cast<const represent_type *>(&self._extention_data);
        else
            return reinterpret_cast<represent_type *>(&self._extention_data);
    }

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
    void init_packet(packet_type &pckt);
    void process_packet(packet_type &&pckt);
};

template<Packet_native_t TPacket>
struct decoy_action : public action<TPacket> {
    using packet_type = decoy_action::packet_type;

public:
    void init_packet(packet_type &pckt) {}
    void process_packet(packet_type &&pckt) {}
};

template<Packet_native_t T, noheap::log_impl::owner_impl::buffer_type _buffer_owner>
struct protocol_native_type {
public:
    using packet_type           = T;
    using action_type           = action<packet_type>;
    using callback_prepare_type = action_type::init_packet_type;
    using callback_handle_type  = action_type::process_packet_type;

public:
    void prepare(packet_type &pckt, buffer_address_type addr,
                 callback_prepare_type callback) const;
    void handle(packet_type &pckt, buffer_address_type addr,
                callback_handle_type callback) const;

public:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        _buffer_owner;

protected:
    static constexpr log_handler log{buffer_owner};
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
    static void prepare(packet_type &pckt, buffer_address_type addr,
                        protocol_type::callback_prepare_type callback) {
        prt.prepare(pckt, addr, callback);
    }
    static void handle(packet_type &&pckt, buffer_address_type addr,
                       protocol_type::callback_handle_type callback) {
        prt.handle(pckt, addr, callback);
    }

public:
    template<typename TSelf>
    decltype(auto) get_native_packet(this TSelf &&self) {
        if constexpr (std::is_const_v<std::remove_reference_t<TSelf>>)
            return *static_cast<
                const typename std::remove_reference_t<TSelf>::packet_type *>(&self);
        else
            return *static_cast<typename std::remove_reference_t<TSelf>::packet_type *>(
                &self);
    }
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

template<Derived_from_action Action, ipv _v>
class udp_stream;

template<typename T>
concept Udp_stream = std::same_as<T, udp_stream<typename T::action_type, T::v>>;

namespace detail {
    struct buffered_packet_type {
        noheap::buffer_bytes_type<max_packet_size, noheap::rbyte> buffer;
        std::size_t                                               accepted_ms;
    };
    using buffer_packets_type = noheap::monotonic_array<
        std::pair<buffer_address_type,
                  noheap::ring_buffer<buffered_packet_type, max_buffered_packets>>,
        max_count_addresses>;
} // namespace detail

template<Derived_from_action Action, ipv _v>
class udp_stream {
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
    using async_future_wrapper = future_wrapper<std::size_t>;

    static_assert(action_type::packet_type::size() < max_packet_size,
                  "Packet size is too long.");

public:
    struct async_validation_type {
        friend udp_stream;

        using callback_type        = std::function<void(std::size_t)>;
        using cancel_callback_type = std::function<void()>;

        enum status_enum : std::size_t {
            in_progress = 0,
            completed,
        };

    public:
        async_validation_type(async_validation_type &&) = default;
        ~async_validation_type() {
            if (status != status_enum::completed)
                validate();
        }

    private:
        async_validation_type(async_future_wrapper &&_async_operation,
                              callback_type          _callback,
                              cancel_callback_type _cancel_callback, status_enum _status)
            : async_operation(std::move(_async_operation)), callback(_callback),
              cancel_callback(_cancel_callback), status(_status) {}

    public:
        void validate() {
            if (status == status_enum::completed)
                return;
            if (!async_operation.is_completed(timeout_ms))
                cancel_callback();

            status = status_enum::completed;
            callback(async_operation.get());
        }

    private:
        cancel_callback_type cancel_callback;
        async_future_wrapper async_operation;
        callback_type        callback;
        status_enum          status;
    };

public:
    udp_stream();
    udp_stream(udp_stream &&) = default;

    template<typename TOther>
    udp_stream(TOther &&stream);
    template<typename TOther>
    udp_stream &operator=(TOther &&stream);

    udp_stream(asio::ip::port_type _port);

    ~udp_stream();

public:
    Action                            &get_action() { return act; }
    decltype(auto)                     get_executor() { return io.get_executor(); }
    port_type                          get_port() const { return port; }
    bool                               get_running() const { return running; }
    const detail::buffer_packets_type &get_buffer_packets() const {
        return buffer_packets;
    }

    void set_running(bool _running) { running = _running; }

    std::size_t run() {
        io.restart();
        return io.run();
    }
    void stop() { io.stop(); }

public:
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    void send_to(TWrapper_packet &pckt, address_type addr);
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    async_validation_type async_send_to(TWrapper_packet &pckt, address_type addr);
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    async_validation_type async_receive_from(TWrapper_packet &pckt, address_type addr);

public:
    static buffer_address_type get_address_bytes(address_type addr);
    static address_type        get_address_object(buffer_address_type addr);
    static address_type        get_address_object(asio::ip::address addr);

private:
    template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
    async_validation_type detail_async_receive_from(TWrapper_packet &pckt,
                                                    address_type     addr,
                                                    bool buffer_packets_is_empty);

    void try_lock();
    void unlock();

    static void handle_error(const system::error_code &ec);

private:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("NSTREAM");
    static constexpr log_handler log{buffer_owner};

private:
    std::timed_mutex                   m;
    std::unique_lock<std::timed_mutex> lock_m{m, std::defer_lock};

    asio::io_context io;
    socket_type      socket;
    Action           act;

    port_type port;
    bool      running;

    detail::buffer_packets_type buffer_packets;
    asio::ip::udp::endpoint     sender_endpoint_tmp;
};

template<Derived_from_action Action, ipv v>
udp_stream<Action, v>::udp_stream(port_type _port)
    : port(_port), running(true), socket(io) {
    system::error_code ec;

    socket.open(get_ipv(), ec);
    handle_error(ec);

    socket.set_option(typename socket_type::reuse_address(true));
    socket.set_option(typename socket_type::broadcast(false));

    socket.bind({get_ipv(), port}, ec);
    handle_error(ec);
}

template<Derived_from_action Action, ipv v>
template<typename TOther>
udp_stream<Action, v>::udp_stream(TOther &&stream) {
    this->operator=(std::forward<TOther>(stream));
}
template<Derived_from_action Action, ipv v>
udp_stream<Action, v>::~udp_stream() {
    stop();
    socket.close();
}

template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
void udp_stream<Action, v>::send_to(TWrapper_packet &pckt, address_type addr) {
    system::error_code      ec;
    asio::ip::udp::endpoint receiver_endpoint(addr, this->port);
    std::decay_t<TWrapper_packet>::prepare(
        pckt,
        this->get_address_bytes(this->get_address_object(receiver_endpoint.address())),
        std::bind(&Action::init_packet, &this->act, std::placeholders::_1));
    this->socket.send_to(asio::const_buffer(pckt.data(), pckt.size()),
                         {receiver_endpoint.address(), receiver_endpoint.port()}, 0, ec);
    handle_error({static_cast<int>(ec.value()), system::system_category()});
}
template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
udp_stream<Action, v>::async_validation_type
    udp_stream<Action, v>::async_send_to(TWrapper_packet &pckt, address_type addr) {
    return async_validation_type(
        std::async(
            std::launch::async,
            [this, &pckt, receiver_endpoint = asio::ip::udp::endpoint(addr, this->port)]()
                -> std::size_t {
                system::error_code ec;

                std::decay_t<TWrapper_packet>::prepare(
                    pckt,
                    this->get_address_bytes(
                        this->get_address_object(receiver_endpoint.address())),
                    std::bind(&Action::init_packet, &this->act, std::placeholders::_1));
                this->socket.send_to(
                    asio::const_buffer(pckt.data(), pckt.size()),
                    {receiver_endpoint.address(), receiver_endpoint.port()}, 0, ec);

                return ec.value();
            }),
        {}, [this]() { this->socket.cancel(); },
        async_validation_type::status_enum::in_progress);
}

template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
udp_stream<Action, v>::async_validation_type
    udp_stream<Action, v>::async_receive_from(TWrapper_packet &pckt, address_type addr) {
    return detail_async_receive_from(pckt, addr, false);
}
template<Derived_from_action Action, ipv v>
template<Compatible_wrapper_packet_with_action<Action> TWrapper_packet>
udp_stream<Action, v>::async_validation_type
    udp_stream<Action, v>::detail_async_receive_from(TWrapper_packet &pckt,
                                                     address_type     addr,
                                                     bool buffer_packets_is_empty) {
    using packet_type = typename std::decay_t<TWrapper_packet>::packet_type;

    const auto handle_receive = [this, required_addr = addr](TWrapper_packet &pckt) {
        unlock();

        const auto buffer_required_addr = get_address_bytes(required_addr);
        auto       native_remote_addr_object =
            this->get_address_object(sender_endpoint_tmp.address());
        auto buffer_remote_addr = get_address_bytes(native_remote_addr_object);

        if (buffer_remote_addr != buffer_required_addr) {
            static constexpr auto make_buffered_packet = [](const TWrapper_packet &pckt) {
                detail::buffered_packet_type packet_tmp;
                packet_tmp.accepted_ms = get_now_ms();
                std::copy(pckt.data(), pckt.data() + pckt.size(),
                          packet_tmp.buffer.begin());
                return packet_tmp;
            };

            try_lock();
            if (const auto &it =
                    std::find_if(buffer_packets.begin(), buffer_packets.end(),
                                 [&buffer_remote_addr](const auto &it) {
                                     return it.first == buffer_remote_addr;
                                 });
                it != buffer_packets.end()) {
                it->second.push(make_buffered_packet(pckt));
            } else if (buffer_packets.size() < max_count_addresses)
                buffer_packets.push_back(typename decltype(buffer_packets)::value_type{
                    buffer_remote_addr, {make_buffered_packet(pckt)}});
            unlock();

            this->detail_async_receive_from(pckt, required_addr, true).validate();
        }

        std::decay_t<TWrapper_packet>::handle(
            std::move(pckt), buffer_remote_addr,
            std::bind(&Action::process_packet, &this->act, std::placeholders::_1));
    };

    // Only 1 thread is allowed to receive packet
    try_lock();

    if (!buffer_packets_is_empty) {
        if (const auto &it = std::find_if(
                buffer_packets.begin(), buffer_packets.end(),
                [buffer_remote_addr = get_address_bytes(addr)](const auto &it) {
                    return it.first == buffer_remote_addr;
                });
            it != buffer_packets.end() && it->second.size() < max_buffered_packets) {
            while (it->second.size()) {
                auto buffered_packet = it->second.pop();

                if (get_now_ms() - buffered_packet.accepted_ms >= timeout_ms)
                    continue;

                *static_cast<packet_type *>(&pckt) =
                    *reinterpret_cast<packet_type *>(buffered_packet.buffer.data());

                std::decay_t<TWrapper_packet>::handle(
                    std::move(pckt), this->get_address_bytes(addr),
                    std::bind(&Action::process_packet, &this->act,
                              std::placeholders::_1));
                return async_validation_type(
                    {}, {}, {}, async_validation_type::status_enum::completed);
            }
        }
    }

    return async_validation_type(
        socket.async_receive_from(asio::mutable_buffer{pckt.data(), pckt.size()},
                                  sender_endpoint_tmp, 0, asio::use_future),
        [func = std::bind(handle_receive, std::ref(pckt))](std::size_t) { func(); },
        [this]() { this->socket.cancel(); },
        async_validation_type::status_enum::in_progress);
}

template<Derived_from_action Action, ipv v>
void udp_stream<Action, v>::try_lock() {
    if (!lock_m.try_lock_for(std::chrono::milliseconds(timeout_ms)))
        handle_error(system::error_code(asio::error::timed_out));
}
template<Derived_from_action Action, ipv v>
void udp_stream<Action, v>::unlock() {
    lock_m.unlock();
}

template<Derived_from_action Action, ipv v>
buffer_address_type udp_stream<Action, v>::get_address_bytes(address_type addr) {
    return noheap::to_new_buffer<buffer_address_type>(addr.to_bytes());
}
template<Derived_from_action Action, ipv v>
udp_stream<Action, v>::address_type
    udp_stream<Action, v>::get_address_object(buffer_address_type addr) {
    return address_type(noheap::to_new_buffer<decltype(address_type{}.to_bytes())>(addr));
}
template<Derived_from_action Action, ipv v>
udp_stream<Action, v>::address_type
    udp_stream<Action, v>::get_address_object(asio::ip::address addr) {
    if constexpr (std::same_as<address_type, asio::ip::address_v4>)
        return addr.to_v4();
    else
        return addr.to_v6();
}

template<Derived_from_action Action, ipv v>
void udp_stream<Action, v>::handle_error(const system::error_code &ec) {
    if (!ec.value())
        return;

    throw noheap::runtime_error(buffer_owner, "Network error: {}", ec.message());
}

} // namespace network

#endif
