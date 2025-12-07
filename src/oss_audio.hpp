#ifndef OSS_AUDIO_HPP
#define OSS_AUDIO_HPP

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>

#include <base_audio.hpp>

class audio : public base_audio<int, int> {
    public:
	audio(audio_stream_t _mode);
	~audio() override;   
 
    public:
	void pread(char* buffer) override;
	void pwrite(const char* buffer) override;
    
    public:
	void init_handle() override;
	void init_params() override;
	void init_sound_device() override;

	void dump_handle() override;
	
	bool init_handle_success() override;
};

audio::audio(audio_stream_t _mode) { init(_mode); }
audio::~audio() { dump(); }
void audio::pread(char* buffer) {
    if(::read(*handle, buffer, buffer_size) == -1)
	    throw_error("Error reading audio.");
}
void audio::pread(const char* buffer) {
    if(::write(*handle, buffer, buffer_size) == -1)
	    throw_error("Error writing audio.");
} 

void audio::init_handle(){
    switch (mode) {
	default:
        case audio_stream_t::playback:
	    handle = open(device_playback.data(), O_RDONLY);
	    break;
	case audio_stream_t::capture:
	    handle = open(device_capture.data(), O_WRONLY);
	    break;
	case audio_stream_t::bidirect:
	    handle = open(device_playback.data(), O_RDWR);
	    break;
    }
}

void audio::init_params(){
    std::size_t cur_param = AFMT_S16_LE;
    if(ioctl(handle, SNDCTL_DSP_SETFMT, &cur_param) == -1 
		|| cur_param != AFMT_S16_LE)
	throw_error("Failed to set the format audio.");	
   
    cur_param = channels;
    if(ioctl(handle, SNDCTL_DSP_CHANNELS, &cur_param) == -1
		|| cur_param != channels)    
	throw_error("Failed to set the count channels for audio.");	

    cur_param = sample_rate;
    if(ioctl(handle, SNDCTL_DSP_SPEED, &cur_param) == -1 
		|| cur_param != sample_rate)
	throw_error("Failed to set the format audio.");
}

void audio::init_sound_device(){
    
}
void audio::dump_handle(){
    close(handle);
}
bool audio::init_handle_success() {
    return static_cast<bool>(handle);
}
}
#endif
