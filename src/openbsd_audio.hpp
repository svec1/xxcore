#ifndef OPENBSD_AUDIO_HPP
#define OPENBSD_AUDIO_HPP

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/audioio.h>

#include <sio_base_audio.hpp>

class audio : public sio_base_audio {
    public:
	audio(audio_stream_t _mode);
	~audio() override;   
 
    protected:
	void init_params() override;
    	void start_audio() override;
    	void stop_audio() override;
};

audio::audio(audio_stream_t _mode) { init(_mode); }
audio::~audio() { dump(); }
void audio::init_params(){
    audio_swpar ap; 

    AUDIO_INITPAR(&ap);

    ap.bits = bits_per_sample;
    ap.bps = bits_per_sample/2;
    ap.sig = 1;
    ap.le = 1;
    ap.rate = sample_rate;
    ap.pchan = channels;
    ap.rchan = channels;
    ap.nblks = period_size;
    ap.round = buffer_size/period_size;

    if(ioctl(handle, AUDIO_SETPAR, &ap) == -1)
        throw_error("Failed to set audio params.");
    
    if(ioctl(handle, AUDIO_GETPAR, &ap) == -1)
        throw_error("Failed to get audio params.");
}
void audio::start_audio() {
    sio_base_audio::start_audio();

    if(mode == audio_stream_t::playback)
	return;

    audio_status status;
    if(ioctl(handle, AUDIO_GETSTATUS, &status) == -1)
        throw_error("Failed to get status of audio device.");
    
    if(status.active || ioctl(handle, AUDIO_START) == -1)
        throw_error("Failed to start audio device.");  
}
void audio::stop_audio(){
    sio_base_audio::stop_audio();
    
    audio_status status;
    if(ioctl(handle, AUDIO_GETSTATUS, &status) == -1)
        throw_error("Failed to get status of audio device.");

    if(status.pause || ioctl(handle, AUDIO_STOP) == -1)
        throw_error("Failed to stop audio device.");
}
#endif
