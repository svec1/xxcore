#include <fstream>

#include "xxcore_service.hpp"

using namespace boost;
using dba = stream_audio::default_base_audio;

constexpr log_handler log_main{{}};
constexpr auto        name_config_file = "xxcore.json";

struct xxcore_config {
    std::string_view             device;
    asio::ip::port_type          port;
    xxcore_service::address_type addr;

    bool keypair_needs_updating = false;
};

// Parses cmd options
static void parse_options(xxcore_config &cfg, int argc, char *argv[]) {
    static constexpr auto throw_usage = [](auto arg, int expected_argument = 0) {
        using re = noheap::runtime_error;

        re::buffer_type buffer;
        auto            end_it = buffer.begin();

        end_it = std::format_to_n(end_it, re::buffer_size,
                                  "Usage: xxcore [-d sound device] [-h "
                                  "IP Host] [-p port]\n")
                     .out;
        if (expected_argument == 1)
            end_it = std::format_to_n(end_it, re::buffer_size,
                                      "Option requires an argument: {}", arg)
                         .out;
        else if (expected_argument == -1)
            end_it =
                std::format_to_n(end_it, re::buffer_size, "Invalid argument: {}", arg)
                    .out;
        else
            end_it =
                std::format_to_n(end_it, re::buffer_size, "Invalid option: {}", arg).out;

        throw re(std::move(buffer));
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
        std::string_view current_value;

        try {
            switch (option[1]) {
                case 'd': {
                    current_value = get_argument(argc, argv, i);
                    cfg.device    = current_value;
                    break;
                }
                case 'h': {
                    current_value = get_argument(argc, argv, i);
                    cfg.addr      = asio::ip::make_address_v4(current_value);
                    break;
                }
                case 'p': {
                    current_value = get_argument(argc, argv, i);
                    cfg.port      = std::stoi(current_value.data());
                    break;
                }
                case 'k': {
                    cfg.keypair_needs_updating = true;
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

// Reads json file
xxcore_service::buffer_config_type read_config() {
    xxcore_service::buffer_config_type buffer_tmp;

    std::ifstream config(name_config_file);
    if (!config.is_open())
        throw noheap::runtime_error("The config file does not exist.");

    config.seekg(0, std::ios_base::end);
    std::size_t size = config.tellg();

    if (size > buffer_tmp.size())
        throw noheap::runtime_error("The config file is too big.");

    config.seekg(0, std::ios_base::beg);
    config.read(buffer_tmp.data(), size);
    return buffer_tmp;
}
// Updates json file
void write_config(xxcore_service::buffer_config_type &buffer) {
    std::ofstream config(name_config_file);
    if (!config.is_open())
        throw noheap::runtime_error("The config file does not exist.");

    config.write(buffer.data(), std::strlen(buffer.data()));
}

void print_cfg(const xxcore_config &cfg) {
    using ca_type = stream_audio::ca_type;
    using na_type = xxcore_service::noise_context_type;

    log_main.to_console(" -- Sound architecture: {}", dba::arsnd_name);
    log_main.to_console(" -- Sound device: {}", cfg.device);
    log_main.to_console(" -- Listening port: {}", cfg.port);
    log_main.to_console(" -- Contact address: {}", cfg.addr.to_string());
    log_main.to_console(" -- Audio config: ");
    log_main.to_console("    | Bitrate: {} kbit/s", dba::cfg.bitrate / 1000);
    log_main.to_console("    | Latency: {} ms", dba::cfg.latency);
    log_main.to_console("    | Channels: {}", dba::cfg.channels);
    log_main.to_console("    | Rate: {} hz", dba::cfg.sample_rate);
    log_main.to_console("    | Sample size: {} bits", dba::cfg.bits_per_sample);
    log_main.to_console(" -- Network config: ");
    log_main.to_console("    | Max count of connections: {}",
                        network::max_count_addresses);
    log_main.to_console("    | Noise pattern: {}",
                        std::string_view(na_type::get_name_id()));
}

int main(int argc, char *argv[]) {
    try {
        xxcore_config cfg = {.device = dba::default_device_playback, .port = 8888};
        parse_options(cfg, argc, argv);
        print_cfg(cfg);

        dba::device_playback = cfg.device;
        dba::device_capture  = cfg.device;

        auto buffer_config = read_config();

        xxcore_service service(std::move(cfg.addr), cfg.port);

        service.configurate(buffer_config, cfg.keypair_needs_updating);
        write_config(buffer_config);

        service.run();

    } catch (noheap::runtime_error &excp) {
        log_main.exception_to_all(excp);
        return 1;
    } catch (std::exception &excp) {
        log_main.to_all("Program panic: {}.", excp.what());
        return 1;
    }

    return 0;
}
