

#include <memory>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "http_proxy_relay_config.hpp"

namespace http_proxy
{
	using json = nlohmann::json;
	using std::cerr;
	http_proxy_relay_config::http_proxy_relay_config()
	{
	}
	template<>
	void http_proxy_relay_config::set_config_value<int>(const std::string& key, const int& value)
	{
		config_map_int[key] = value;
	}
	template<>
	void http_proxy_relay_config::set_config_value<std::string>(const std::string& key, const std::string& value)
	{
		config_map_str[key] = value;
	}
	template<>
	int http_proxy_relay_config::get_config_value<int>(const std::string& key)const
	{
		auto iter = config_map_int.find(key);
		if (iter == config_map_int.end())
		{
			throw std::invalid_argument(key);
		}
		else
		{
			return iter->second;
		}
	}
	template<>
	std::string http_proxy_relay_config::get_config_value<std::string>(const std::string& key)const
	{
		auto iter = config_map_str.find(key);
		if (iter == config_map_str.end())
		{
			throw std::invalid_argument(key);
		}
		else
		{
			return iter->second;
		}
	}
	bool http_proxy_relay_config::load_config(const std::string& config_filename)
	{
		std::ifstream the_file(config_filename);
		std::string config_data((std::istreambuf_iterator<char>(the_file)), (std::istreambuf_iterator<char>()));

		json json_obj(config_data);
		try
		{
			json_obj = json::parse(config_data);
		}
		catch (std::exception& e)
		{
			std::cerr << e.what() << std::endl;
			std::cerr << "failed to parse config" << std::endl;
			return false;
		}
		if (!json_obj.is_object())
		{
			std::cerr << "the data should be a map" << std::endl;
			return false;
		}
		if (json_obj.find("proxy_server_address") == json_obj.end())
		{
			std::cerr << "Could not find \"proxy_server_address\" in config or it's value is not a string" << std::endl;
			return false;
		}
		set_config_value("proxy_server_address", json_obj["proxy_server_address"].get<std::string>());
		if (json_obj.find("proxy_server_port") == json_obj.end())
		{
			std::cerr << "Could not find \"proxy_server_port\" in config or it's value is not a number" << std::endl;
			return false;
		}

		set_config_value("proxy_server_port", json_obj["proxy_server_port"].get<int>());
		if (json_obj.find("bind_address") != json_obj.end()) {
			set_config_value("bind_address", json_obj["bind_address"].get<std::string>());
		}
		else {
			set_config_value("bind_address", std::string("0.0.0.0"));
		}
		if (json_obj.find("listen_port") != json_obj.end()) {
			set_config_value("listen_port", json_obj["listen_port"].get<int>());
		}
		else {
			set_config_value("listen_port", 8090);
		}
		if (json_obj.find("timeout") != json_obj.end()) {
			int timeout = static_cast<int>(json_obj["timeout"]);
			set_config_value("timeout", timeout < 30 ? 30 : timeout);
		}
		else {
			set_config_value("timeout", 240);
		}
		if (json_obj.find("workers") != json_obj.end()) {
			int threads = json_obj["workers"];
			set_config_value("workers", threads < 1 ? 1 : (threads > 16 ? 16 : threads));
		}
		else {
			set_config_value("workers", 4);
		}
		for (const auto& one_log_level : { "log_level", "console_log_level", "file_log_level" })
		{
			if (json_obj.find(one_log_level) != json_obj.end())
			{
				set_config_value(one_log_level, int(spdlog::level::from_str(json_obj[one_log_level])));
			}
			else
			{
				set_config_value(one_log_level, int(spdlog::level::level_enum::off));
			}
		}
		if (json_obj.find("log_file") != json_obj.end())
		{
			set_config_value("log_file", static_cast<std::string>(json_obj["log_file"]));
		}
		else
		{
			set_config_value("log_file", std::string("ahps_log.txt"));
		}
		return true;
	}


	std::string http_proxy_relay_config::get_bind_address() const
	{
		return this->get_config_value<std::string>("bind_address");
	}

	int http_proxy_relay_config::get_listen_port() const
	{
		return this->get_config_value<int>("listen_port");
	}

	int http_proxy_relay_config::get_timeout() const
	{
		return this->get_config_value<int>("timeout");
	}

	int http_proxy_relay_config::get_workers() const
	{
		return this->get_config_value<int>("workers");
	}

	http_proxy_relay_config& http_proxy_relay_config::get_instance()
	{
		static http_proxy_relay_config instance;
		return instance;
	}
	spdlog::level::level_enum http_proxy_relay_config::get_log_level() const
	{
		return spdlog::level::level_enum(this->get_config_value<int>("log_level"));
	}
	spdlog::level::level_enum http_proxy_relay_config::get_console_log_level() const
	{
		return spdlog::level::level_enum(this->get_config_value<int>("console_log_level"));
	}
	spdlog::level::level_enum http_proxy_relay_config::get_file_log_level() const
	{
		return spdlog::level::level_enum(this->get_config_value<int>("file_log_level"));
	}
	std::string http_proxy_relay_config::get_log_file_name() const
	{
		auto file_iter = config_map_str.find("log_file");
		if (file_iter == config_map_str.end())
		{
			return "relay_log.txt";
		}
		else
		{
			return file_iter->second;
		}
	}

	std::uint32_t http_proxy_relay_config::increase_connection_count()
	{
		return connection_count++;
	}
	std::string http_proxy_relay_config::get_proxy_server_address() const
	{
		return this->get_config_value<std::string>("proxy_server_address");
	}

	int http_proxy_relay_config::get_proxy_server_port() const
	{
		return this->get_config_value<int>("proxy_server_port");
	}
}