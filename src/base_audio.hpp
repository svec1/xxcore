#ifndef BASE_AUDIO_HPP
#define BASE_AUDIO_HPP

#include <utils.hpp>

enum audio_stream_t { playback = 0, capture, bidirect };

static constexpr std::string_view audio_stream_t_to_string(audio_stream_t mode){
    switch(mode){
	case audio_stream_t::playback:
	    return "PLAYBACK";
	case audio_stream_t::capture:
	    return "CAPTURE";
	case audio_stream_t::bidirect:
	    return "BIDIRECT";
    }
}

template <typename THandle, typename TParams>
class base_audio {
   public:
    static constexpr std::string_view arsnd_name = ARSND_NAME_D;
    static constexpr std::size_t arsnd_name_size = ARSND_NAME_SIZE_D;
    static constexpr std::string_view default_device_playback = "default";
    static constexpr std::string_view default_device_capture = "default";

    static constexpr std::size_t bits_per_sample = 16;
    static constexpr std::size_t sample_rate = 44100;
    static constexpr std::size_t channels = 2;
    static constexpr std::size_t period_size = 512;
    static constexpr std::size_t buffer_size =
        period_size * channels * bits_per_sample / 8;

    using buffer_t = std::array<char, buffer_size>;

   public:
    base_audio() = default;
    virtual ~base_audio() = default;

   public:
    void init(audio_stream_t _mode);
    void dump();

    constexpr void read(buffer_t& buffer);
    constexpr void write(const buffer_t& buffer);

   public:
    virtual void init_handle() = 0;
    virtual void init_params() = 0;
    virtual void init_sound_device() = 0;

    virtual void dump_handle() = 0;

    virtual bool init_handle_success() = 0;

   protected:
    virtual void pread(char* buffer) = 0;
    virtual void pwrite(const char* buffer) = 0;

    template<typename... Args>
    void throw_error(std::format_string<Args...> format, Args&&... args){
 	noheap::runtime_error::buffer_t buffer;
    	std::fill_n(buffer.begin(), buffer_size, 0);
	if(format.get().size()){
		auto end_it = std::format_to(buffer.begin(), "{}: ", arsnd_name);
		std::format_to(end_it, format, std::forward<Args>(args)...);
    	}
	throw noheap::runtime_error(std::move(buffer));
    }

   public:
    static std::string_view device_playback;
    static std::string_view device_capture;
	
   protected:
    THandle handle;
    static TParams params;
    
    audio_stream_t mode;
    bool possible_bidirect_stream, params_is_init = false;
};

template <typename THandle, typename TParams>
void base_audio<THandle, TParams>::init(audio_stream_t _mode) {
    try {
	mode = _mode;
	possible_bidirect_stream = (device_playback == device_capture);

 	if(mode == audio_stream_t::bidirect && !possible_bidirect_stream)
	   throw_error("For bidirectional, different device names were specified."); 
        
	init_handle();
	if (!init_handle_success()) throw_error("");
	if (!params_is_init){ 
	    init_params();
	    params_is_init = true;
	}
        init_sound_device();
    } catch (noheap::runtime_error& excp) {
	throw_error("Failed to open the stream({}:{})\n{}",
                        audio_stream_t_to_string(mode),
                        (!(int)mode ? device_playback : device_capture),
			excp.what());
    }
}
template <typename THandle, typename TParams>
void base_audio<THandle, TParams>::dump() {
    dump_handle();
}
template <typename THandle, typename TParams>
constexpr void base_audio<THandle, TParams>::read(buffer_t& buffer){
    if(mode == audio_stream_t::playback)
	throw_error("Failed to read of the stream({}).", audio_stream_t_to_string(mode));
    std::fill_n(buffer.begin(), buffer_size, 0);
    pread(buffer.data());
}
template <typename THandle, typename TParams>
constexpr void base_audio<THandle, TParams>::write(const buffer_t& buffer){
    if(mode == audio_stream_t::capture)
	throw_error("Failed to write of the stream({}).", audio_stream_t_to_string(mode));
    pwrite(buffer.data());
}
template <typename THandle, typename TParams>
TParams base_audio<THandle, TParams>::params;

template <typename THandle, typename TParams>
std::string_view base_audio<THandle, TParams>::device_playback =
    base_audio<THandle, TParams>::default_device_playback;
template <typename THandle, typename TParams>
std::string_view base_audio<THandle, TParams>::device_capture =
    base_audio<THandle, TParams>::default_device_capture;

#endif
