#ifndef AAUDIO_HPP
#define AAUDIO_HPP

#include <alsa/asoundlib.h>

#include <cstdio>
#include <format>
#include <functional>
#include <string>
#include <string_view>

#define snd_call(func, ...)                  \
    {                                        \
        snd_call_(func, #func, __VA_ARGS__); \
    }

using byte = char;

template <typename T, typename... Args>
void snd_call_(T&& func, std::string_view name_func, Args&&... args) {
    if (int ret = func(args...); ret < 0) {
        throw std::runtime_error(
            std::format("Error({}): {}", name_func, snd_strerror(ret)));
    }
}

class audio {
   public:
    audio(snd_pcm_stream_t _mode);
    ~audio();

   private:
    void open_pcm();

    static void init_params(snd_pcm_t* pcm_handle,
                            snd_pcm_hw_params_t* hw_params);

   public:
    static std::string_view device;
    static constexpr unsigned int sample_rate = 44100, channels = 2,
                                  period_size = 256,
                                  buffer_size = period_size * channels * 2;

    static constexpr unsigned int period_time =
        (buffer_size / (sample_rate * channels * 2)) * 1000;

   protected:
    static constexpr snd_pcm_access_t access = SND_PCM_ACCESS_RW_INTERLEAVED;
    static constexpr snd_pcm_format_t format = SND_PCM_FORMAT_S16_LE;

    static snd_pcm_hw_params_t* hw_params;

   private:
    static unsigned int counter_astream;

   protected:
    snd_pcm_t* pcm_handle = nullptr;
    snd_pcm_stream_t mode;
};
audio::audio(snd_pcm_stream_t _mode) : mode(_mode) {
    try {
        open_pcm();

        if (!hw_params) {
            snd_call(snd_pcm_hw_params_malloc, &hw_params);
            init_params(pcm_handle, hw_params);
        }
        snd_call(snd_pcm_hw_params, pcm_handle, hw_params);
        snd_call(snd_pcm_prepare, pcm_handle);

        ++counter_astream;
    } catch (std::runtime_error& err) {
        throw std::runtime_error(
            std::format("Failed to open the stream({}:{}): {}", device,
                        !(int)mode ? "PLAYBACK" : "CAPTURE", err.what()));
    }
}
audio::~audio() {
    snd_pcm_close(pcm_handle);
    if (!counter_astream--) snd_pcm_hw_params_free(hw_params);
}
void audio::open_pcm() {
    snd_call(snd_pcm_open, &pcm_handle, device.data(), mode, 0);
}
void audio::init_params(snd_pcm_t* pcm_handle, snd_pcm_hw_params_t* hw_params) {
    static snd_pcm_uframes_t pcm_period_size = 940;

    snd_call(snd_pcm_hw_params_any, pcm_handle, hw_params);

    snd_call(snd_pcm_hw_params_set_access, pcm_handle, hw_params, access);
    snd_call(snd_pcm_hw_params_set_format, pcm_handle, hw_params, format);
    snd_call(snd_pcm_hw_params_set_channels, pcm_handle, hw_params, channels);
    snd_call(snd_pcm_hw_params_set_rate, pcm_handle, hw_params, sample_rate, 0);

    snd_call(snd_pcm_hw_params_set_period_size_near, pcm_handle, hw_params,
             &pcm_period_size, nullptr);
}

std::string_view audio::device = "";
snd_pcm_hw_params_t* audio::hw_params = nullptr;
unsigned int audio::counter_astream = 0;

#endif
