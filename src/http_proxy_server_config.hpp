/*
 *    http_proxy_server_config.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_SERVER_CONFIG_HPP
#define AZURE_HTTP_PROXY_SERVER_CONFIG_HPP

#include <cassert>
#include <map>
#include <stdexcept>
#include <string>
#include <spdlog/spdlog.h>


namespace azure_proxy {

class http_proxy_server_config {
	std::map<std::string,int> config_map_int;
	std::map<std::string, std::string> config_map_str;
private:
	template<typename T>
	T get_config_value(const std::string& key) const;
	template<typename T>
	void set_config_value(const std::string& key, const T& value);
	http_proxy_server_config();
	
public:
	bool load_config(const std::string& config_filename);
	std::string get_bind_address() const;
	int get_listen_port() const;
	std::string get_rsa_private_key() const;
	int get_timeout() const;
	int get_workers() const;
	bool enable_auth() const;
	spdlog::level::level_enum get_log_level() const;
	std::string get_log_file_name() const;
	static http_proxy_server_config& get_instance();
};

} // namespace azure_proxy

#endif
