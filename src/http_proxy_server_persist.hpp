#pragma once
#include <atomic>
#include <spdlog/spdlog.h>

#include <asio.hpp>
using error_code = asio::error_code;

namespace azure_proxy {

	class http_proxy_server_persist {
		asio::io_service& io_service;
		asio::ip::tcp::acceptor acceptor;
		std::shared_ptr<spdlog::logger> logger;
	public:

		http_proxy_server_persist(asio::io_service& io_service);

		
		void run();
	private:
		void start_accept();
	};

} // namespace azure_proxy

