#ifndef RAWSIO_AUDIO_HPP
#define RAWSIO_AUDIO_HPP

#include <sys/audioio.h>
#include <sys/ioctl.h>

class audio : public base_audio<int, audio_swpar> {
    public:
	audio(audio_stream_t _mode);
	~audio() override;
    
    public:
	void read(char* buffer) override;
	void write(char* buffer) override;
    
    public:
	void init_handle() override;
	void init_params() override;
	void init_sound_device() override;

	void dump_handle() override;
	
	bool init_handle_success() override;
};

audio::audio(audio_stream_t _mode) {
    init(_mode);
}
audio::~audio() { dump(); }
void audio::read(char* buffer) {
    if(::read(*handle, buffer, buffer_size) == -1)
	    throw std::runtime_error("Error reading audio.");
}
void audio::write(char* buffer) {
    if(::write(*handle, buffer, buffer_size) == -1)
	    throw std::runtime_error("Error writing audio.");
} 

void audio::init_handle(){
    static int dsp_st = open(device_playback.data(), O_RDWR);
    handle = &dsp_st;
}

void audio::init_params(){
    std::size_t cur_param = AFMT_S16_LE;
    if(ioctl(*handle, SNDCTL_DSP_SETFMT, &cur_param) == -1 
		|| cur_param != AFMT_S16_LE)
	throw std::runtime_error("Failed to set the format audio.");	
   
    cur_param = channels;
    if(ioctl(*handle, SNDCTL_DSP_CHANNELS, &cur_param) == -1
		|| cur_param != channels)    
	throw std::runtime_error("Failed to set the count channels for audio.");	

    cur_param = sample_rate;
    if(ioctl(*handle, SNDCTL_DSP_SPEED, &cur_param) == -1 
		|| cur_param != sample_rate)
	throw std::runtime_error("Failed to set the format audio.");
}

void audio::init_sound_device(){
    
}
void audio::dump_handle(){
    close(*handle);
}


#endif
