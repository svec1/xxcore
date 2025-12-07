#ifndef AAUDIO_HPP
#define AAUDIO_HPP

#include <alsa/asoundlib.h>

#include <base_audio.hpp>

class audio : public base_audio<snd_pcm_t*, snd_pcm_hw_params_t> {
   public:
    audio(audio_stream_t _mode);
    ~audio() override;

   private:
    void init_handle() override;
    void init_params() override;
    void init_sound_device() override;

    void dump_handle() override;
 
    bool init_handle_success() override;
   
   protected:
    void pread(char* buffer) override;
    void pwrite(const char* buffer) override;
   
   private:
    template <typename T, typename... Args>
    static void throw_if(T&& func, Args&&... args) {
	static int ret;
        if (ret = func(args...); ret < 0)
	    throw_error(snd_strerror(ret));
    }

   protected:
    static constexpr snd_pcm_access_t access = SND_PCM_ACCESS_RW_INTERLEAVED;
    static constexpr snd_pcm_format_t format = SND_PCM_FORMAT_S16_LE;
};
audio::audio(audio_stream_t _mode) { init(_mode); }
audio::~audio() { dump(); }
void audio::pread(char* buffer) {
    static std::size_t ret;
    while ((ret = snd_pcm_readi(handle, buffer, period_size)) < 0)
        throw_if(snd_pcm_recover, handle, period_size, 0);
}
void audio::pwrite(const char* buffer) {
    static std::size_t ret;
    while ((ret = snd_pcm_writei(handle, buffer, period_size)) < 0)
        throw_if(snd_pcm_prepare, handle);
}
void audio::init_handle() {
    switch (mode) {
	default:
        case audio_stream_t::playback:
            throw_if(snd_pcm_open, &handle, device_playback.data(),
                     SND_PCM_STREAM_PLAYBACK, 0);
            break;
        case audio_stream_t::capture:
            throw_if(snd_pcm_open, &handle, device_capture.data(),
                     SND_PCM_STREAM_CAPTURE, 0);
            break;
        case audio_stream_t::bidirect:
	    throw_error("Bidirect mode is not supported.");
    }
}
void audio::init_params() {
    static snd_pcm_uframes_t pcm_buffer_size = 4096;
    static snd_pcm_uframes_t pcm_period_size = 940;

    throw_if(snd_pcm_hw_params_alloc, &params);
    throw_if(snd_pcm_hw_params_any, handle, &params);

    throw_if(snd_pcm_hw_params_set_access, handle, &params, access);
    throw_if(snd_pcm_hw_params_set_format, handle, &params, format);
    throw_if(snd_pcm_hw_params_set_channels, handle, &params, channels);
    throw_if(snd_pcm_hw_params_set_rate, handle, &params, sample_rate, 0);

    throw_if(snd_pcm_hw_params_set_buffer_size_near, handle, &params,
             &pcm_buffer_size);
    throw_if(snd_pcm_hw_params_set_period_size_near, handle, &params,
             &pcm_period_size, nullptr);
}
void audio::init_sound_device() {
    throw_if(snd_pcm_hw_params, handle, &params);
    throw_if(snd_pcm_prepare, handle);
}
void audio::dump_handle() {
    snd_pcm_drain(handle);
    snd_pcm_close(handle);
}
bool audio::init_handle_success() {
    return static_cast<bool>(handle);
}
#endif
