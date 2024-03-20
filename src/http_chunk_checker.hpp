#pragma once

#include <cassert>
#include <cctype>
#include <iterator>
#include <type_traits>
#include <cstdint>
namespace http_proxy
{

	enum class http_chunk_check_state
	{
		chunk_size_start,
		chunk_size,
		chunk_ext,
		chunk_size_cr,
		chunk_data,
		chunk_data_cr,
		chunk_last,
		chunk_last_cr,
		chunk_complete,
		chunk_check_failed
	};

	class http_chunk_checker
	{
		http_chunk_check_state state;
		std::uint32_t current_chunk_size;
		std::uint32_t current_chunk_size_has_read;
	public:
		http_chunk_checker() : state(http_chunk_check_state::chunk_size_start), current_chunk_size(0), current_chunk_size_has_read(0)
		{
		}

		bool is_complete() const
		{
			return this->state == http_chunk_check_state::chunk_complete;
		}
		void reset()
		{
			state = http_chunk_check_state::chunk_size_start;
			current_chunk_size = 0;
			current_chunk_size_has_read = 0;
		}
		bool is_fail() const
		{
			return this->state == http_chunk_check_state::chunk_check_failed;
		}
		std::uint32_t chunk_size() const
		{
			return current_chunk_size;
		}
		
		std::pair<bool, std::size_t> check(const char* begin, const char* end)
		{
			assert(!this->is_fail());
			auto iter = begin;
			for ( ;iter != end; ++iter)
			{
				switch (this->state)
				{
				case http_chunk_check_state::chunk_size_start:
					if (std::isxdigit(static_cast<char>(*iter)))
					{
						this->current_chunk_size = (*iter) >= 'A' ? std::toupper(static_cast<char>(*iter)) - 'A' + 10 : *iter - '0';
						this->current_chunk_size_has_read = 0;
						this->state = http_chunk_check_state::chunk_size;
						continue;
					}
					break;
				case http_chunk_check_state::chunk_size:
					if (std::isxdigit(static_cast<char>(*iter)))
					{
						this->current_chunk_size = this->current_chunk_size * 16 + ((*iter) >= 'A' ? std::toupper(static_cast<char>(*iter)) - 'A' + 10 : *iter - '0');
						continue;
					}
					else if (*iter == ';' || *iter == ' ')
					{
						this->state = http_chunk_check_state::chunk_ext;
						continue;
					}
					else if (*iter == '\r')
					{
						this->state = http_chunk_check_state::chunk_size_cr;
						continue;
					}
					break;
				case http_chunk_check_state::chunk_ext:
					//完全忽略具体的chunk选项。。。。 虽然除了忽略也没啥办法
					if (*iter == '\r')
					{
						this->state = http_chunk_check_state::chunk_size_cr;
					}
					continue;
				case http_chunk_check_state::chunk_size_cr:
					if (*iter == '\n')
					{
						if (this->current_chunk_size == 0)
						{
							this->state = http_chunk_check_state::chunk_last;
						}
						else
						{
							this->state = http_chunk_check_state::chunk_data;
						}
						continue;
					}
					break;
				case http_chunk_check_state::chunk_data:
					if (this->current_chunk_size_has_read < this->current_chunk_size)
					{
						++this->current_chunk_size_has_read;
						continue;
					}
					else
					{
						if (*iter == '\r')
						{
							this->state = http_chunk_check_state::chunk_data_cr;
							continue;
						}
					}
					break;
				case http_chunk_check_state::chunk_data_cr:
					if (*iter == '\n')
					{
						this->state = http_chunk_check_state::chunk_size_start;
						continue;
					}
					break;
				case http_chunk_check_state::chunk_last:
					if (*iter == '\r')
					{
						this->state = http_chunk_check_state::chunk_last_cr;
						continue;
					}
					break;
				case http_chunk_check_state::chunk_last_cr:
					if (*iter == '\n')
					{
						this->state = http_chunk_check_state::chunk_complete;
						continue;
					}
					break;
				case http_chunk_check_state::chunk_complete:
					break;
				default:
					assert(false);
					break;
				}
				this->state = http_chunk_check_state::chunk_check_failed;
				return std::make_pair(false, iter - begin);
			}
			return std::make_pair(true, iter - begin);
		}
	};

} // namespace http_proxy
