#ifndef NET_HPP
#define NET_HPP

#include <unistd.h>

#include <array>
#include <boost/asio.hpp>

using namespace boost;

template <unsigned int _buffer_size = 4096>
struct packet_native_t {
    using buffer_el_t = char;
    template <unsigned int size_buffer>
    using buffer_t = std::array<buffer_el_t, size_buffer>;

   public:
    static constexpr unsigned int buffer_size = _buffer_size;

   public:
    packet_native_t() = default;

    virtual buffer_t<buffer_size> to_bytes() const {
        buffer_t<buffer_size> arr;
        const buffer_el_t* bytes_p =
            reinterpret_cast<const buffer_el_t*>(this) + 8;

        std::memcpy(arr.data(), bytes_p, buffer_size);
        return arr;
    }
    virtual buffer_el_t* get_buffer() {
        return reinterpret_cast<buffer_el_t*>(this) + 8;
    }

   public:
    buffer_t<buffer_size> buffer;
};

class nstream;

template <typename T, typename F, F _prepare, F _was_accepted>
class packet : public std::enable_if_t<
                   std::is_base_of_v<packet_native_t<T::buffer_size>, T> &&
                       std::is_invocable_v<F, decltype(std::declval<T&>())>,
                   T> {
    friend class nstream;

   public:
    using packet_t = T;
    using cfunction_t = F;

   public:
    static constexpr unsigned int size = sizeof(T) - 8;

   public:
    packet() = default;
    packet(T&& pckg) : T(pckg) {}

   public:
    static void prepare(packet_t& pckt) { _prepare(pckt); }
    static void was_accepted(packet_t& pckt) { _was_accepted(pckt); }
};

template <typename T>
struct applied_native_protocol {
    static constexpr void prepare(T& pckt) {}
    static constexpr void was_accepted(T& pckt) {}

    using cfunction_t = decltype(prepare);
};

class nstream final {
   public:
    nstream(asio::io_context& io, asio::ip::address addr,
            asio::ip::port_type port)
        : sock(io), p(addr, port), i_address(get_default_interface_address()) {
        sock.open(p.protocol(), ec);
        sock.bind(p);

        sock.set_option(asio::socket_base::broadcast(true));
        sock.set_option(asio::socket_base::reuse_address(true));

        if (ec.value())
            throw std::runtime_error(
                std::format("Failed to open udp socket({}).", ec.message()));
    }

   public:
    template <typename T, typename aprotocol = applied_native_protocol<T>>
    std::enable_if_t<std::is_same_v<
        T, packet<typename T::packet_t, typename aprotocol::cfunction_t,
                  aprotocol::prepare, aprotocol::was_accepted>>>
    send_to(T&& pckt) {
        T::prepare(pckt);
        sock.send_to(boost::asio::buffer(pckt.to_bytes()), p, 0, ec);
        if (ec.value())
            throw std::runtime_error(
                std::format("Failed to send packet({}).", ec.message()));
    }

    template <typename T, typename aprotocol = applied_native_protocol<T>>
    std::enable_if_t<std::is_same_v<
        T, packet<typename T::packet_t, typename aprotocol::cfunction_t,
                  aprotocol::prepare, aprotocol::was_accepted>>>
    receive_last(T& pckt) {
        typename T::template buffer_t<T::size> buffer_tmp;
        asio::ip::udp::endpoint p_sender;
        do {
            p_sender = {};
            unsigned int len = sock.receive_from(
                boost::asio::buffer(buffer_tmp), p_sender, 0, ec);
            if (ec.value())
                throw std::runtime_error(
                    std::format("Failed to process packet({}).", ec.message()));
            else if (len != T::size)
                throw std::runtime_error("Undefined package.");
        } while (p_sender.address() == i_address);

        std::printf("%s\n", p_sender.address().to_string().data());

        std::copy(buffer_tmp.begin(), buffer_tmp.end(), pckt.get_buffer());
        T::was_accepted(pckt);
    }

   private:
    static asio::ip::address get_default_interface_address() {
        FILE* pipe_ip_default =
            popen("ip route show default | awk '/default/ {print $9}'", "r");

        std::string ip_str("", 16);
        fread(ip_str.data(), 1, ip_str.size(), pipe_ip_default);
        pclose(pipe_ip_default);

        if (auto it = ip_str.find_last_of("\n"); it != ip_str.npos)
            ip_str.erase(it, ip_str.size() - 1);

        return asio::ip::make_address(ip_str);
    }

   private:
    asio::ip::udp::socket sock;
    asio::ip::udp::endpoint p;
    asio::ip::address i_address;

    boost::system::error_code ec;
};

#endif
