#ifndef XXCORE_SERVICE_HPP
#define XXCORE_SERVICE_HPP

#include <boost/json.hpp>
#include <boost/json/src.hpp>

#include "audio_flow.hpp"
#include "essu_session.hpp"
#include "stream_audio.hpp"

using namespace boost;

class xxcore_service {
public:
    static constexpr std::size_t max_size_config = BOOST_JSON_STACK_BUFFER_SIZE;
    using buffer_config_type = noheap::buffer_type<char, max_size_config>;

    using noise_context_type = essu_session::noise_context_type;
    using address_type       = essu_session::net_stream_udp::address_type;
    using port_type          = essu_session::net_stream_udp::port_type;

private:
    // Config for noise handshake.
    struct config_type {
        noise::noise_role role;

        noise_context_type::dh_key_type local_private_key;
        noise_context_type::dh_key_type local_public_key;
        noise_context_type::dh_key_type remote_public_key;
        noise_context_type::dh_key_type pre_shared_key;
    };

    // For test
    struct test_action final
        : network::action<essu_session::wrapper_packet_type::packet_type> {
        static constexpr std::size_t max_stream_size = 32;

        using audio_flow_type = audio_flow<max_stream_size>;

    public:
        constexpr void init_packet(test_action::packet_type &pckt) override {
            audio_flow_type::buffer_type buffer_tmp;
            audio.pop(buffer_tmp);
            pckt->units[0].header.type = decltype(pckt->units[0].header.type)::data;
            std::copy(reinterpret_cast<noheap::rbyte *>(buffer_tmp.begin()),
                      reinterpret_cast<noheap::rbyte *>(buffer_tmp.end()),
                      pckt->units[0].buffer.begin());
            for (std::size_t i = 1; i < pckt->units.size(); ++i) {
                pckt->units[i].header.type = decltype(pckt->units[0].header.type)::data;
                pckt->units[i].header.flag = decltype(pckt->units[0].header.flag)::drop;
            }
        }
        constexpr void process_packet(test_action::packet_type &&pckt) override {
            audio_flow_type::buffer_type buffer_tmp;
            std::copy(pckt->units[0].buffer.begin(),
                      pckt->units[0].buffer.begin() + buffer_tmp.size(),
                      reinterpret_cast<noheap::rbyte *>(buffer_tmp.begin()));
            // audio.push(std::move(buffer_tmp), false);
        }

    private:
        audio_flow_type audio;
    };

public:
    xxcore_service(address_type &&_addr, asio::ip::port_type _port);

    void run();
    void configurate(buffer_config_type &buffer, bool generate_new_keypair);

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
    essu_session stream(addr, port);

    stream.establish_connection(
        config.role, {}, {config.local_private_key, config.local_public_key},
        std::move(config.remote_public_key), std::move(config.pre_shared_key));
    stream.run_stream_session<test_action>();
}

void xxcore_service::configurate(buffer_config_type &buffer, bool generate_new_keypair) {
    log.to_all("Setting of configurate.");

    {
        static constexpr std::string_view role_string          = "role";
        static constexpr std::string_view local_private_string = "privk";
        static constexpr std::string_view local_public_string  = "pubk";
        static constexpr std::string_view remote_public_string = "r_pubk";
        static constexpr std::string_view pre_shared_string    = "psk";

        noheap::buffer_bytes_type<BOOST_JSON_STACK_BUFFER_SIZE, noheap::ubyte>
            json_buffer_tmp;

        json::static_resource json_mr(json_buffer_tmp.data(), json_buffer_tmp.size());

        json::value data(&json_mr);
        data = json::parse(buffer.data(), &json_mr);

        auto keypair_tmp = noise_context_type::generate_keypair();

        const auto &get_bytes_key = [&](const std::string_view field_name,
                                        auto                  &buffer_key) {
            using buffer_key_hex_type = decltype(noheap::hex_encode(buffer_key));

            auto value_p = data.try_at(field_name);
            if (!value_p)
                return;
            auto string_p = value_p->try_as_string();
            if (!string_p)
                throw noheap::runtime_error(buffer_owner,
                                            "Field of key must be a string.");

            if (generate_new_keypair && field_name == local_private_string) {
                *string_p  = std::string_view(noheap::hex_encode(keypair_tmp.priv));
                buffer_key = std::move(keypair_tmp.priv);
                return;
            } else if (generate_new_keypair && field_name == local_public_string) {
                *string_p  = std::string_view(noheap::hex_encode(keypair_tmp.pub));
                buffer_key = std::move(keypair_tmp.pub);
                return;
            }

            if (string_p->size() >= buffer.size())
                throw noheap::runtime_error(
                    buffer_owner, "The specified key field has a large size:\n\t{}: {}",
                    buffer.size(), field_name, *string_p);

            buffer_key_hex_type buffer_key_hex{};
            std::copy(reinterpret_cast<noheap::rbyte *>(string_p->begin()),
                      reinterpret_cast<noheap::rbyte *>(string_p->end()),
                      reinterpret_cast<noheap::rbyte *>(buffer_key_hex.begin()));
            buffer_key = noheap::to_buffer<decltype(buffer_key)>(
                noheap::hex_decode(buffer_key_hex));
        };

        auto value_p = data.try_at(role_string);
        if (!value_p)
            throw noheap::runtime_error(buffer_owner, "Field of role not specified.");
        auto role_p = value_p->try_as_string();
        if (!role_p)
            throw noheap::runtime_error(buffer_owner, "Field of role must be a string.");

        config.role = noise::get_noise_role(*role_p);
        get_bytes_key(local_private_string, config.local_private_key);
        get_bytes_key(local_public_string, config.local_public_key);
        get_bytes_key(remote_public_string, config.remote_public_key);
        get_bytes_key(pre_shared_string, config.pre_shared_key);

        buffer = {};

        json::serializer sz;
        sz.reset(&data);
        sz.read(buffer.data(), buffer.size());
    }
}
#endif
