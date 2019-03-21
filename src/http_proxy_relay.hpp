#pragma once

#include <atomic>
#include <asio.hpp>
using error_code = asio::error_code;

#include <spdlog/spdlog.h>

namespace http_proxy
{

	class http_proxy_relay
	{
		asio::io_service& io_service;
		asio::ip::tcp::acceptor acceptor;
		std::shared_ptr<spdlog::logger> logger;
	public:

		http_proxy_relay(asio::io_service& io_service);

		void run();
	private:
		void start_accept();
	};

} // namespace http_proxy

