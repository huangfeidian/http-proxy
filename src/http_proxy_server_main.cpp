/*
 *    http_proxy_server_main.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <iostream>

#include "http_proxy_server_config.hpp"
#include "http_proxy_server.hpp"

#ifdef WITH_LOG
#include <ctime>
#include <sstream>
#include <iomanip>
#include <fstream>
#endif

int main(int argc, char** argv)
{
#ifdef WITH_LOG
	std::time_t now = std::time(nullptr);
	std::string time_format = "%Y-%m-%d %H-%M-%S";
	std::ostringstream oss;
	oss << std::put_time(std::gmtime(&now), time_format.c_str());
	std::string time_str = oss.str();
	std::ofstream dumpfile(time_str + "-server_log.txt");
#endif
	std::string default_config_filename = "server.json";
	std::string config_filename;
	if (argc == 1)
	{
		config_filename = default_config_filename;
		std::cout << "using default config file server.json" << std::endl;
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
		auto& config = http_proxy_server_config::get_instance();
		if (config.load_config(config_filename)) {
			std::cout << "Azure Http Proxy Server" << std::endl;
			std::cout << "bind address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
			asio::io_service io_service;
#ifdef WITH_LOG
			http_proxy_server server(io_service,dumpfile);
#else 
			http_proxy_server server(io_service);
#endif
			server.run();
		}
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
