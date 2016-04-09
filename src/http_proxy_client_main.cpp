/*
 *    http_proxy_client_main.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <iostream>

#ifdef ASIO_STANDALONE
#include <asio.hpp>
using error_code = asio::error_code;

#else
#include <boost/asio.hpp>
namespace asio = boost::asio;
using error_code = boost::system::error_code;
#endif
#ifdef WITH_LOG
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>
#endif
#include "http_proxy_client.hpp"
#include "http_proxy_client_stat.hpp"
#include "http_proxy_client_config.hpp"


int main(int argc, char** argv)
{
#ifdef WITH_LOG
	std::time_t now = std::time(nullptr);
	std::string time_format = "%Y-%m-%d %H-%M-%S";
	std::ostringstream oss;
	oss<<std::put_time(std::gmtime(&now),time_format.c_str());
	std::string time_str = oss.str();
	std::ofstream dumpfile(time_str+"-client_dump.txt");
#endif
	std::string default_config_filename = "client.json";
	std::string config_filename;
	if (argc == 1)
	{
		config_filename = default_config_filename;
		std::cout << "using default config file client.json" << std::endl;
	}
	else
	{
		if (argc == 2)
		{
			config_filename = argv[1];
			std::cout << "using config file " << config_filename << std::endl;
			
		}
		else
		{
			std::cout << "the only optional argument is the config filename" << std::endl;
			std::cout << "you have provided more argument than expected" << std::endl;
			exit(0);
		}
		
	}
	using namespace azure_proxy;
	try {
		auto& config = http_proxy_client_config::get_instance();
		if (config.load_config(config_filename)) {
			std::cout << "Azure Http Proxy Client" << std::endl;
			std::cout << "server address: " << config.get_proxy_server_address() << ':' << config.get_proxy_server_port() << std::endl;
			std::cout << "local address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
			std::cout << "cipher: " << config.get_cipher() << std::endl;
			asio::io_service io_service;
			http_proxy_client_stat::get_instance().start_stat(io_service);
#ifdef WITH_LOG
			http_proxy_client client(io_service,dumpfile);
#else
			http_proxy_client client(io_service);
#endif
			client.run();
		}
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}
}
