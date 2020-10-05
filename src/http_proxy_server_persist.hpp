#pragma once
#include <atomic>

#include <asio.hpp>

#include <spdlog/spdlog.h>

using error_code = asio::error_code;

namespace http_proxy {

	class http_proxy_server_persist {
		asio::io_context& io_context;
		asio::ip::tcp::acceptor acceptor;
		std::shared_ptr<spdlog::logger> logger;
	public:

		http_proxy_server_persist(asio::io_context& io_context);

		
		void run();
	private:
		void start_accept();
	};

} // namespace http_proxy

