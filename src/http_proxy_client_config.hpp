/*
 *    http_proxy_client_config.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_PROXY_CLIENT_CONFIG_HPP
#define AZURE_HTTP_PROXY_CLIENT_CONFIG_HPP

#include <cassert>
#include <map>
#include <stdexcept>
#include <string>
#include <nlohmann/json.hpp>

namespace azure_proxy
{
	using json = nlohmann::json;
	class http_proxy_client_config
	{
	private:
		std::map<std::string, int> config_map_int;
		std::map<std::string, std::string> config_map_str;
	private:
		template<typename T>
		T get_config_value(const std::string& key) const;
		template<typename T>
		void set_config_value(const std::string& key, T value);
		http_proxy_client_config();
	public:
		bool load_config(const std::string& config_filename);
		std::string get_proxy_server_address() const;
		int get_proxy_server_port() const;
		std::string get_bind_address() const;
		int get_listen_port() const;
		std::string get_rsa_public_key() const;
		std::string get_cipher() const;
		int get_timeout() const;
		int get_workers() const;

		static http_proxy_client_config& get_instance();
	};

} // namespace azure_proxy

#endif
