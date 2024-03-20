﻿#pragma once

#include <random>
#include <memory>
#include <cassert>
#include <chrono>
#include <mutex>

namespace http_proxy
{

	class key_generator
	{
		std::mt19937 gen;
		std::mutex mtx;
		key_generator()
		{
			//用时间与new出来一个变量的地址做异或 也是蛮拼的
			std::uint64_t seed = reinterpret_cast<std::uint64_t>(std::unique_ptr<int>(new int(0)).get()) ^ static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count());
			this->gen.seed(static_cast<unsigned int>(seed));
		}
	public:
		void generate(unsigned char* out, std::size_t length)
		{
			assert(out);
			std::uniform_int_distribution<unsigned short> dis(0, 255);
			std::lock_guard<std::mutex> lck(this->mtx);
			for (std::size_t i = 0; i < length; ++i)
			{
				out[i] = static_cast<unsigned char>(dis(this->gen));
			}
		}
		static key_generator& get_instance()
		{
			//全局静态方法
			static key_generator instance;
			return instance;
		}
	};
	
}
