#pragma once

#include <atomic>
#include <asio.hpp>
using error_code = asio::error_code;

#include <spdlog/spdlog.h>
#include "http_proxy_client_session_manager.hpp"

namespace http_proxy
{

	class http_proxy_client_persist
	{
		asio::io_service& io_service;
		asio::ip::tcp::acceptor acceptor;
		std::shared_ptr<spdlog::logger> logger;
        std::vector<std::shared_ptr<http_proxy_client_session_manager>> _session_managers;
	public:

		http_proxy_client_persist(asio::io_service& io_service);

		void run();
	private:
		void start_accept();
	};

} // namespace http_proxy

