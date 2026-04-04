#ifndef AUDIO_FLOW_HPP
#define AUDIO_FLOW_HPP

#include "stream_audio.hpp"
#include "utils.hpp"

struct flow_audio {
    static constexpr std::size_t max_stream_size = 32;
    using buffer_type                            = typename stream_audio::buffer_type;

public:
    flow_audio();
    ~flow_audio();

public:
    void pop(buffer_type &buffer);
    void push(buffer_type &&buffer, bool lost);

private:
    void check_running();
    void wait_stopping();

private:
    std::mutex               in_stream_m, out_stream_m;
    std::future<void>        in_stream, out_stream;
    std::atomic<bool>        running = true;
    std::atomic<std::size_t> filled  = 0;

    stream_audio io_audio;

    noheap::ring_buffer<buffer_type, max_stream_size>                in_stream_buffer;
    noheap::ring_buffer<std::optional<buffer_type>, max_stream_size> out_stream_buffer;
};

#endif
