#ifndef SUDIO_HPP
#define SUDIO_HPP

#include <sndio.h>

#include <base_audio.hpp>

class audio : public base_audio<sio_hdl*, sio_par> {
   public:
    audio(audio_stream_t mode);
    ~audio() override;

   public:
    void pread(char* buffer) override;
    void pwrite(const char* buffer) override;

   private:
    void init_handle() override;
    void init_params() override;
    void init_sound_device() override;

    void dump_handle() override;

    bool init_handle_success() override;
};

audio::audio(audio_stream_t _mode) { init(_mode); }
audio::~audio() { dump(); }
void audio::pread(char* buffer) {
    static std::size_t ret = 0;
    ret = sio_read(handle, buffer, buffer_size);

    if (ret <= 0) throw_error("Error reading audio.");
}
void audio::pwrite(const char* buffer) {
    static std::size_t ret = 0;
    ret = sio_write(handle, buffer, buffer_size);

    if (ret <= 0) throw_error("Error writing audio.");
}
void audio::init_handle() {
    switch (mode) {
        default:
        case audio_stream_t::playback:
            handle = sio_open(device_playback.data(), SIO_PLAY, 0);
            break;
        case audio_stream_t::capture:
            handle = sio_open(device_capture.data(), SIO_REC, 0);
            break;
	case audio_stream_t::bidirect:
            handle = sio_open(device_playback.data(), SIO_PLAY | SIO_REC, 0);
            break;
    }
}
void audio::init_params() {
    sio_initpar(&params);

    params.bits = bits_per_sample;
    params.sig = 1;
    params.le = SIO_LE_NATIVE;
    params.pchan = channels;
    params.rate = sample_rate;
}
void audio::init_sound_device() {
    if (!sio_setpar(handle, &params))
        throw_error("Failed to set audio params.");
    if (!sio_start(handle))
        throw_error("Failed to start audio device.");
}
void audio::dump_handle() {
    sio_stop(handle);
    sio_close(handle);
}
bool audio::init_handle_success() {
    return static_cast<bool>(handle);
}

#endif
