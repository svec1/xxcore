#include "unix_udp_voice_service.hpp"

static constexpr std::size_t max_count_addrs = 16;
static constexpr log_handler log_main{{}};

using namespace boost;

using uuv_service = unix_udp_voice_service<max_count_addrs>;

struct vcu_config {
    std::string_view device;
    asio::ip::port_type port;
    noheap::monotonic_array<uuv_service::nstream_t::ipv_t, max_count_addrs>
        addrs;
};

static void parse_options(vcu_config &cfg, int argc, char *argv[]) {
    static constexpr auto throw_usage = [](auto arg,
                                           int expected_argument = 0) {
        noheap::runtime_error::buffer_t buffer;

        auto end_it = buffer.begin();
        end_it = std::format_to_n(end_it, noheap::runtime_error::buffer_size,
                                  "Usage: alsa_tcp_voice [-D sound device] [-h "
                                  "IP Host] [-p port]\n")
                     .out;
        if (expected_argument == 1)
            end_it =
                std::format_to_n(end_it, noheap::runtime_error::buffer_size,
                                 "Option requires an argument: {}", arg)
                    .out;
        else if (expected_argument == -1)
            end_it =
                std::format_to_n(end_it, noheap::runtime_error::buffer_size,
                                 "Invalid argument: {}", arg)
                    .out;
        else
            end_it =
                std::format_to_n(end_it, noheap::runtime_error::buffer_size,
                                 "Invalid option: {}", arg)
                    .out;

        throw noheap::runtime_error(std::move(buffer));
    };

    static constexpr auto get_argument = [](int argc, char *argv[], int &i) {
        if (std::strlen(argv[i]) > 2)
            return argv[i] + 2;
        else {
            if (argc <= i + 1)
                throw_usage(argv[i], 1);
            else if (argv[i + 1][0] == '-')
                throw_usage(argv[i + 1], -1);

            return argv[++i];
        }
    };

    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] != '-')
            throw_usage(argv[i]);

        std::string_view option = argv[i];
        std::string_view current_value = get_argument(argc, argv, i);

        try {
            switch (option[1]) {
            case 'D': {
                cfg.device = current_value;
                break;
            }
            case 'h': {
                auto addr = asio::ip::make_address_v4(current_value);
                if (std::find(cfg.addrs.begin(), cfg.addrs.end(), addr) ==
                    cfg.addrs.end()) {
                    if (cfg.addrs.size() == max_count_addrs)
                        throw_usage(current_value, -1);

                    cfg.addrs.push_back(addr);
                }
                break;
            }
            case 'p': {
                cfg.port = std::stoi(current_value.data());
                break;
            }
            default:
                throw_usage(option[1]);
            }
        } catch (system::system_error &) {
            throw_usage(current_value, -1);
        }
    }
}

void print_cfg(const vcu_config &cfg) {
    log_main.to_console(" -- Sound architecture: {}", audio::arsnd_name);
    log_main.to_console(" -- Sound device: {}", cfg.device);
    log_main.to_console(" -- Listening port: {}", cfg.port);
    log_main.to_console(" -- Possible contact addresses:");
    std::for_each(cfg.addrs.begin(), cfg.addrs.end(), [](auto &addr) {
        log_main.to_console("    | {}", addr.to_string());
    });
}

int main(int argc, char *argv[]) {
    try {
        vcu_config cfg = {.device = audio::default_device_playback,
                          .port = 8888};
        parse_options(cfg, argc, argv);
        print_cfg(cfg);

        audio::device_playback = cfg.device;
        audio::device_capture = cfg.device;

        uuv_service vsc(cfg.addrs, cfg.port);
    } catch (noheap::runtime_error &excp) {
        log_main.exception_to_all(excp);
        return 1;
    } catch (std::exception &excp) {
        log_main.to_all("Program panic: {}.", excp.what());
        return 1;
    }

    return 0;
}
