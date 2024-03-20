
#include <iostream>

#include "http_proxy_server_config.hpp"
#include "http_proxy_server_persist.hpp"



int main(int argc, char** argv)
{
	using std::cerr;
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
	using namespace http_proxy;
	try {
		auto& config = http_proxy_server_config::get_instance();
		if (config.load_config(config_filename)) {
			std::cout << "Http Proxy Server" << std::endl;
			std::cout << "bind address: " << config.get_bind_address() << ':' << config.get_listen_port() << std::endl;
			asio::io_context io_context;
			http_proxy_server_persist server(io_context);

			server.run();
		}
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
