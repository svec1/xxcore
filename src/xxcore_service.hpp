#ifndef XXCORE_SERVICE_HPP
#define XXCORE_SERVICE_HPP

#include <boost/json.hpp>
#include <boost/json/src.hpp>

#include "audio_flow.hpp"
#include "crypto.hpp"
#include "essu_session.hpp"
#include "network.hpp"
#include "stream_audio.hpp"

using namespace boost;

class xxcore_service {
public:
    static constexpr network::ipv                v = network::ipv::v4;
    static constexpr essu::transport_data_config transport_config{
        noise::ecdh_type::x25519, 256};

    static constexpr std::size_t max_size_config = 4096;
    using buffer_config_type = noheap::buffer_type<char, max_size_config>;

    using wrapper_packet_type =
        network::wrapper_packet<essu::transport_packet_type<transport_config>,
                                essu::transport_protocol_type<transport_config>>;
    using stream_udp_type =
        network::net_stream_udp<network::decoy_action<wrapper_packet_type::packet_type>,
                                v>;
    using noise_context_type =
        wrapper_packet_type::extention_data_type::transport_unit_type::noise_context_type;
    using address_type = stream_udp_type::address_type;
    using port_type    = stream_udp_type::port_type;

private:
    // Config for noise handshake.
    struct config_type {
        noise::noise_pattern pattern;
        noise::noise_role    role;

        noise_context_type::dh_key_type local_private_key;
        noise_context_type::dh_key_type local_public_key;
        noise_context_type::dh_key_type remote_public_key;
        noise_context_type::dh_key_type pre_shared_key;
    };

    // For test
    struct audio_action final : network::action<wrapper_packet_type::packet_type> {
        static constexpr std::size_t max_stream_size = 32;

        using audio_flow_type = audio_flow<max_stream_size>;

    public:
        constexpr void init_packet(audio_action::packet_type &pckt) override {
            audio_flow_type::buffer_type buffer_tmp;

            audio.pop(buffer_tmp);
            std::copy(reinterpret_cast<noheap::rbyte *>(buffer_tmp.begin()),
                      reinterpret_cast<noheap::rbyte *>(buffer_tmp.end()),
                      pckt->packets[0].buffer.begin());

            for (std::size_t i = 1; i < pckt->packets.size(); ++i)
                pckt->packets[i].header.flag =
                    decltype(pckt->packets[0].header.flag)::drop;
        }
        constexpr void process_packet(audio_action::packet_type &&pckt) override {
            audio_flow_type::buffer_type buffer_tmp;
            std::copy(pckt->packets[0].buffer.begin(), pckt->packets[0].buffer.end(),
                      reinterpret_cast<noheap::rbyte *>(buffer_tmp.begin()));
            audio.push(std::move(buffer_tmp), false);
        }

    private:
        audio_flow_type audio;
    };

public:
    xxcore_service(address_type &&_addr, asio::ip::port_type _port);

    void run();
    void configurate(buffer_config_type &&buffer);

private:
    static constexpr noheap::log_impl::owner_impl::buffer_type buffer_owner =
        noheap::log_impl::create_owner("UUV_SERVICE");
    static constexpr log_handler log{buffer_owner};

private:
    config_type config{};

    address_type addr;
    port_type    port;
};

xxcore_service::xxcore_service(address_type &&_addr, asio::ip::port_type _port)
    : addr(_addr), port(_port) {
}

void xxcore_service::run() {
    essu_session<v, wrapper_packet_type, audio_action> stream(addr, port);

    stream.establish_connection(config.pattern, config.role, {},
                                {config.local_private_key, config.local_public_key},
                                std::move(config.remote_public_key),
                                config.pre_shared_key);
    stream.run_stream_session();
}

void xxcore_service::configurate(buffer_config_type &&buffer) {
    log.to_all("Setting of configurate.");

    {
        static constexpr std::string_view role_string          = "role";
        static constexpr std::string_view pattern_string       = "pattern";
        static constexpr std::string_view local_private_string = "local_private_key";
        static constexpr std::string_view local_public_string  = "local_public_key";
        static constexpr std::string_view remote_public_string = "remote_public_key";
        static constexpr std::string_view pre_shared_string    = "pre_shared_key";

        noheap::buffer_bytes_type<8192, noheap::ubyte> json_buffer_tmp;
        noheap::buffer_bytes_type<1024>                buffer_tmp{};

        json::static_resource json_mr(json_buffer_tmp.data(), json_buffer_tmp.size());

        json::value data(&json_mr);
        data = json::parse(buffer.data(), &json_mr);

        const auto &get_bytes_key = [&](const std::string_view field_name, auto &buffer) {
            auto value_p = data.try_at(field_name);
            if (!value_p)
                return;

            auto string_p = value_p->try_as_string();
            if (string_p) {
                if (string_p->size() >= buffer.size())
                    throw noheap::runtime_error(
                        buffer_owner,
                        "The specified key field has a large size:\n\t{}: {}",
                        buffer.size(), field_name, *string_p);
                std::copy(reinterpret_cast<noheap::rbyte *>(string_p->begin()),
                          reinterpret_cast<noheap::rbyte *>(string_p->end()),
                          buffer.begin());
            } else
                throw noheap::runtime_error(buffer_owner,
                                            "Field of key must be a string.");
        };

        auto value_p = data.try_at(role_string);
        if (!value_p)
            throw noheap::runtime_error(buffer_owner, "Field of role not specified.");
        auto role_p = value_p->try_as_string();
        if (!role_p)
            throw noheap::runtime_error(buffer_owner, "Field of role must be a string.");

        value_p = data.try_at(pattern_string);
        if (!value_p)
            throw noheap::runtime_error(buffer_owner, "Field of pattern  not specified.");
        auto pattern_p = value_p->try_as_string();
        if (!pattern_p)
            throw noheap::runtime_error(buffer_owner,
                                        "Field of pattern must be a string.");

        config.pattern = noise::get_noise_pattern(*pattern_p);
        config.role    = noise::get_noise_role(*role_p);
        get_bytes_key(local_private_string, config.local_private_key);
        get_bytes_key(local_public_string, config.local_public_key);
        get_bytes_key(remote_public_string, config.remote_public_key);
        get_bytes_key(pre_shared_string, config.pre_shared_key);
    }
}
#endif
