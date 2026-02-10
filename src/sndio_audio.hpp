#ifndef SUDIO_HPP
#define SUDIO_HPP

#include <sndio.h>
#include <sys/poll.h>

#include "base_audio.hpp"

template<audio_config _cfg>
class audio : public base_audio<_cfg> {
public:
    audio(stream_audio_mode mode);
    ~audio() override;

protected:
    void pread(audio::buffer_type::value_type *buffer) override;
    void pwrite(const audio::buffer_type::value_type *buffer) override;

private:
    static void sndio_init_params(sio_par &params);

private:
    sio_hdl *handle;
    sio_par params;
};

template<audio_config _cfg>
audio<_cfg>::audio(stream_audio_mode _mode) : base_audio<_cfg>(_mode) {
    switch (this->mode) {
        default:
        case stream_audio_mode::playback:
            this->handle = sio_open(this->device_playback.data(), SIO_PLAY, 0);
            break;
        case stream_audio_mode::capture:
            this->handle = sio_open(this->device_capture.data(), SIO_REC, 0);
            break;
        case stream_audio_mode::bidirect:
            this->handle = sio_open(this->device_playback.data(), SIO_PLAY | SIO_REC, 0);
            break;
    }
    sndio_init_params(params);

    if (!sio_setpar(this->handle, &params))
        audio::template throw_error<audio::stream_audio_error::failed_set_params>();
    if (!sio_getpar(this->handle, &params))
        audio::template throw_error<audio::stream_audio_error::failed_get_params>();

    if (!sio_start(this->handle))
        audio::template throw_error<audio::stream_audio_error::failed_start>();
}
template<audio_config _cfg>
audio<_cfg>::~audio() {
    if (!sio_stop(this->handle))
        audio::template throw_error<audio::stream_audio_error::failed_stop>();
    sio_close(this->handle);
}
template<audio_config _cfg>
void audio<_cfg>::pread(audio::buffer_type::value_type *buffer) {
    if (sio_read(this->handle, buffer, this->cfg.buffer_size) <= 0)
        audio::template throw_error<audio::stream_audio_error::error_reading>();
}
template<audio_config _cfg>
void audio<_cfg>::pwrite(const audio::buffer_type::value_type *buffer) {
    if (sio_write(this->handle, buffer, this->cfg.buffer_size) <= 0)
        audio::template throw_error<audio::stream_audio_error::error_writing>();
}
template<audio_config _cfg>
void audio<_cfg>::sndio_init_params(sio_par &params) {
    sio_initpar(&params);

    params.bits     = audio::cfg.bits_per_sample;
    params.bps      = audio::cfg.bytes_per_sample;
    params.sig      = 1;
    params.le       = SIO_LE_NATIVE;
    params.pchan    = audio::cfg.channels;
    params.rchan    = audio::cfg.channels;
    params.rate     = audio::cfg.sample_rate;
    params.appbufsz = audio::cfg.buffer_size;
}

#endif
