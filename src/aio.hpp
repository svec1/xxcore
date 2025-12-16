#ifndef AIO_HPP
#define AIO_HPP

#if defined(ALSA)
#define ARSND_NAME_D "ALSA"
#define ARSND_NAME_SIZE_D 4
#include <alsa_audio.hpp>
#elif defined(SNDIO)
#define ARSND_NAME_D "SNDIO"
#define ARSND_NAME_SIZE_D 5 
#include <sndio_audio.hpp>
#elif defined(FREEBSD_AUDIO)
#define ARSND_NAME_D "FREEBSD_AUDIO"
#define ARSND_NAME_SIZE_D 13 
#include <oss_audio.hpp>
#elif defined(OPENBSD_AUDIO)
#define ARSND_NAME_D "OPENBSD_AUDIO"
#define ARSND_NAME_SIZE_D 13 
#include <openbsd_audio.hpp>
#elif defined(NETBSD_AUDIO)
#define ARSND_NAME_D "NETBSD_AUDIO"
#define ARSND_NAME_SIZE_D 12
#include <netbsd_audio.hpp>
#endif

#include <array>
#include <span>

class input : private audio {
   public:
    input();

   public:
    audio::buffer_t get_samples();
};
class output : private audio {
   public:
    output();

   public:
    void play_samples(const audio::buffer_t& bytes);
};

input::input() : audio(audio_stream_t::capture) {}
audio::buffer_t input::get_samples() {
    audio::buffer_t bytes;
    read(bytes);
    return bytes;
}

output::output() : audio(audio_stream_t::playback) {}
void output::play_samples(const audio::buffer_t& bytes) {
    write(bytes);
}

#endif
