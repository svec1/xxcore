#ifndef OPENBSD_AUDIO_HPP
#define OPENBSD_AUDIO_HPP

#include <sys/audioio.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "sio_base_audio.hpp"

template<audio_config _cfg>
class audio : public sio_base_audio<_cfg> {
public:
    audio(stream_audio_mode _mode);
    ~audio() override;

protected:
    void init_params() override;
};

template<audio_config _cfg>
audio<_cfg>::audio(stream_audio_mode _mode) : sio_base_audio<_cfg>(_mode) {
    audio_status status;
    if (ioctl(this->handle, AUDIO_GETSTATUS, &status) == -1)
        audio::template throw_error<audio::stream_audio_error::failed_get_status>();

    if (!status.pause)
        return;

    if (ioctl(this->handle, AUDIO_START) == -1)
        audio::template throw_error<audio::stream_audio_error::failed_start>();
}

template<audio_config _cfg>
audio<_cfg>::~audio() {
    audio_status status;
    if (ioctl(this->handle, AUDIO_GETSTATUS, &status) == -1)
        audio::template throw_error<audio::stream_audio_error::failed_get_status>();

    if (status.pause)
        return;

    if (ioctl(this->handle, AUDIO_STOP) == -1)
        audio::template throw_error<audio::stream_audio_error::failed_stop>();
}
template<audio_config _cfg>
void audio<_cfg>::init_params() {
    audio_swpar ap;

    AUDIO_INITPAR(&ap);

    ap.sig   = 1;
    ap.le    = 1;
    ap.bits  = audio::cfg.bits_per_sample;
    ap.bps   = audio::cfg.bytes_per_sample;
    ap.msb   = 0;
    ap.rate  = audio::cfg.sample_rate;
    ap.pchan = audio::cfg.channels;
    ap.rchan = audio::cfg.channels;
    ap.nblks = 4;
    ap.round = audio::cfg.buffer_size / 4;

    if (ioctl(this->handle, AUDIO_SETPAR, &ap) == -1)
        audio::template throw_error<audio::stream_audio_error::failed_set_params>();

    if (ioctl(this->handle, AUDIO_GETPAR, &ap) == -1)
        audio::template throw_error<audio::stream_audio_error::failed_get_params>();
}
#endif
