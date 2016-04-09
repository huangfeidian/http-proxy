/*
 *    http_proxy_server.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_SERVER_HPP
#define AZURE_HTTP_PROXY_SERVER_HPP

#ifdef ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;

#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;
#endif


namespace azure_proxy {

	class http_proxy_server {
		asio::io_service& io_service;
		asio::ip::tcp::acceptor acceptor;

	public:

		http_proxy_server(asio::io_service& io_service);

		
		void run();
	private:
		void start_accept();
	};

} // namespace azure_proxy

#endif
