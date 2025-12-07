#ifndef BASE_MIXER_HPP
#define BASE_MIXER_HPP

template<typename THandle>
class base_mixer{
   public:
	base_mixer();
	virtual ~base_mixer() = default;

   public:
	virtual void init_handle() = 0;

	virtual void set_gain(unsigned float value) = 0;
	virtual void mute(bool value) = 0;

   public:
	static constexpr std::string_view default_device_mixer = "default";
	
	static std::string_view device_mixer;
	static bool mute;

   private:
	THandle handle;	
};

template<typename THandle>
std::string_view base_mixer<THandle>::device_mixer = base_mixer<THandle>::default_device_mixer;
template<typename THandle>
bool base_mixer<THandle>::mute = false;

#endif
