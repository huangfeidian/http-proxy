
#include <iostream>

#include <asio.hpp>
using error_code = asio::error_code;

#include "http_proxy_client_persist.hpp"
#include "http_proxy_client_stat.hpp"
#include "http_proxy_client_config.hpp"


int main(int argc, char** argv)
{
	using std::cerr;
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
	using namespace http_proxy;
	try {
		auto& config = http_proxy_client_config::get_instance();
		if (config.load_config(config_filename)) {
			std::cout << "Http Proxy Client" << std::endl;
			std::cout << "server address: " << config.get_proxy_server_address() << ':' << config.get_proxy_server_port() << std::endl;
			std::cout << "local address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
			std::cout << "cipher: " << config.get_cipher() << std::endl;
			asio::io_service io_service;
			http_proxy_client_stat::get_instance().start_stat(io_service);

			http_proxy_client_persist client(io_service);

			client.run();
		}
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}
}
