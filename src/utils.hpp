#ifndef UTILS_HPP
#define UTILS_HPP

#include <exception>
#include <algorithm>
#include <format>
#include <array>
#include <memory_resource>
#include <vector>
#include <cstdio>
#include <string_view>

namespace noheap{

template<typename... Args>
void println(std::format_string<Args...> format, Args&&... args){
    static constexpr std::size_t buffer_size = 512;   
    std::array<char, buffer_size> buffer;
    std::fill_n(buffer.begin(), buffer_size, 0);
    
    auto end_it = std::format_to(buffer.begin(), format, std::forward<Args>(args)...); 
    *end_it = '\n';
    *(end_it+1) = '\0';

    std::printf("%s", buffer.data()); 
}

class runtime_error : public std::exception{
   public:	
	static constexpr std::size_t buffer_size = 512;   
	using buffer_t = std::array<char, buffer_size>;

   public:
	template<typename... Args>
	runtime_error(std::format_string<Args...> format, Args&&... args){
    	    std::fill_n(buffer.begin(), buffer_size, 0);

    	    if(format.get().size()){
    	    	auto end_it = std::format_to(buffer.begin(), format, std::forward<Args>(args)...); 
    		*end_it = '\0'; 
    	    }
	} 
	runtime_error(buffer_t&& _buffer) : buffer(_buffer){} 
	~runtime_error() override = default;

   public:
	const char* what() const noexcept override {
	    return buffer.data();
	}
	
   private:
	buffer_t buffer;
};

class monotonic_buffer_resource_static final : public std::pmr::memory_resource{
   public:
	monotonic_buffer_resource_static(char* _buffer, std::size_t _buffer_size) : buffer(_buffer), buffer_size(_buffer_size) {}
	
   protected:
	void* do_allocate(std::size_t bytes, std::size_t alignment){
	    static constexpr auto find_alignment_bytes = [](std::size_t offset, std::size_t alignment){
	    	std::size_t offset_end = offset;
		while(offset_end % alignment) offset_end += offset_end % alignment;
		return offset_end-offset; 
	    };
	    const std::size_t bytes_alignment = find_alignment_bytes(offset, alignment);	
	     
	    offset += bytes+bytes_alignment;

	    if(offset >= buffer_size)
		throw runtime_error("The allocator buffer is full: {} bytes were allocated.", buffer_size);
	    return buffer+offset-bytes-bytes_alignment;
	}
	void do_deallocate(void* p, std::size_t bytes, std::size_t alignment){
	}
	bool do_is_equal(const std::pmr::memory_resource& other) const noexcept{
	    try{
	    	if(dynamic_cast<decltype(this)>(&other)->buffer == this->buffer)
		    return true;
	    }
	    catch(...){}
	    return false;
	}

   private:
	char* buffer;
	std::size_t buffer_size, offset = 0;
};

template<typename T, std::size_t max_count>
struct vector_stack {
	static constexpr std::size_t buffer_size = sizeof(T)*max_count;

   private:
	std::array<char, buffer_size> buffer;
	monotonic_buffer_resource_static mbr{buffer.data(), buffer.size()};
	std::pmr::polymorphic_allocator<T> allocator{&mbr};
	
   public:
	std::pmr::vector<T> data{allocator};
};

}

#endif
