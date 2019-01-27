/*
 *    http_proxy_client_connection.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_CONNECTION_HPP
#define AZURE_HTTP_PROXY_CLIENT_CONNECTION_HPP

#include <array>
#include <chrono>
#include <memory>
#include <vector>

#ifdef ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;

#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;
#endif

#include "encrypt.hpp"
#include "http_header_parser.hpp"
#include "http_proxy_connection_context.hpp"

#include "http_proxy_connection.hpp"

namespace azure_proxy
{

	class http_proxy_client_connection : public http_proxy_connection
	{

	private:
		http_request_parser _request_parser;
		http_response_parser _response_parser;
	public:
		virtual ~http_proxy_client_connection();
		static std::shared_ptr<http_proxy_client_connection> create(asio::ip::tcp::socket&& ua_socket, asio::ip::tcp::socket&& _server_socket,std::shared_ptr<spdlog::logger> logger, std::uint32_t in_connection_count);
		virtual void start();
	private:
		bool init_cipher();
	};

} // namespace azure_proxy

#endif
