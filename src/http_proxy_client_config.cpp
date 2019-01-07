/*
 *    http_proxy_client_config.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <algorithm>
#include <cctype>
#include <fstream>
#include <memory>
#include <streambuf>
#include <iostream>
#include "encrypt.hpp"
#include "http_proxy_client_config.hpp"


namespace azure_proxy
{
	using std::cerr;
	using namespace std;
	http_proxy_client_config::http_proxy_client_config()
	{
	}
	template<>
	void http_proxy_client_config::set_config_value<int>(const std::string& key, const int& value)
	{
		config_map_int[key] = value;
	}
	template<>
	void http_proxy_client_config::set_config_value<std::string>(const std::string& key, const std::string& value)
	{
		config_map_str[key] = value;
	}

	template<>
	int http_proxy_client_config::get_config_value<int>(const std::string& key)const
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
	std::string http_proxy_client_config::get_config_value<std::string>(const std::string& key)const
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

	bool http_proxy_client_config::load_config(const std::string& config_filename)
	{
		std::ifstream the_file(config_filename);
		std::string config_data((std::istreambuf_iterator<char>(the_file)), (std::istreambuf_iterator<char>()));
		bool rollback = true;
		std::shared_ptr<bool> auto_rollback(&rollback, [this](bool* rollback)
		{
			if (*rollback)
			{
				this->config_map_int.clear();
				this->config_map_str.clear();
			}
		});
		json json_obj;
		try
		{
			json_obj=json::parse(config_data);
		}
		catch (std::exception& e)
		{
			std::cerr << e.what() << std::endl;
			std::cerr << "Failed to parse config" << std::endl;
			return false;
		}
		if (!json_obj.is_object())
		{
			std::cerr << "The data shoud be  a map" << std::endl;
			return false;
		}
		if (json_obj.find("proxy_server_address")==json_obj.end())
		{
			std::cerr << "Could not find \"proxy_server_address\" in config or it's value is not a string" << std::endl;
			return false;
		}
		set_config_value("proxy_server_address", json_obj["proxy_server_address"].get<std::string>());
		if (json_obj.find("proxy_server_port")==json_obj.end())
		{
			std::cerr << "Could not find \"proxy_server_port\" in config or it's value is not a number" << std::endl;
			return false;
		}
		set_config_value("proxy_server_port" , json_obj["proxy_server_port"].get<int>());
		if (json_obj.find("bind_address")!=json_obj.end())
		{
			set_config_value("bind_address", json_obj["bind_address"].get<std::string>());
		}
		else
		{
			set_config_value("bind_address", std::string("127.0.0.1"));
		}
		if (json_obj.find("listen_port")!=json_obj.end())
		{
			set_config_value("listen_port",json_obj["listen_port"].get<int>());
		}
		else
		{
			set_config_value("listen_port",8089);
		}
		if (json_obj.find("rsa_public_key")==json_obj.end())
		{
			std::cerr << "Could not find \"rsa_public_key\" in config or it's value is not a string" << std::endl;
			return false;
		}
		const std::string& rsa_public_key = json_obj["rsa_public_key"];
		try
		{
			rsa rsa_pub(rsa_public_key);
			if (rsa_pub.modulus_size() < 128)
			{
				std::cerr << "Must use RSA keys of at least 1024 bits" << std::endl;
				return false;
			}
		}
		catch (const std::exception&)
		{
			std::cerr << "The value of rsa_public_key is bad" << std::endl;
			return false;
		}
		set_config_value("rsa_public_key",rsa_public_key);
		if (json_obj.find("cipher")!=json_obj.end())
		{
			std::string cipher = json_obj["cipher"];
			for (auto& ch : cipher)
			{
				ch = std::tolower(static_cast<unsigned char>(ch));
			}
			bool is_supported_cipher = false;
			if (cipher.size() > 3 && std::equal(cipher.begin(), cipher.begin() + 4, "aes-"))
			{
				if (cipher.size() > 8 && cipher[7] == '-'
					&& (std::equal(cipher.begin() + 4, cipher.begin() + 7, "128")
					|| std::equal(cipher.begin() + 4, cipher.begin() + 7, "192")
					|| std::equal(cipher.begin() + 4, cipher.begin() + 7, "256")
					))
				{
					if (std::equal(cipher.begin() + 8, cipher.end(), "cfb")
						|| std::equal(cipher.begin() + 8, cipher.end(), "cfb128")
						|| std::equal(cipher.begin() + 8, cipher.end(), "cfb8")
						|| std::equal(cipher.begin() + 8, cipher.end(), "cfb1")
						|| std::equal(cipher.begin() + 8, cipher.end(), "ofb")
						|| std::equal(cipher.begin() + 8, cipher.end(), "ofb128")
						|| std::equal(cipher.begin() + 8, cipher.end(), "ctr")
						|| std::equal(cipher.begin() + 8, cipher.end(), "ctr128"))
					{
						is_supported_cipher = true;
					}
				}
			}
			if (!is_supported_cipher)
			{
				std::cerr << "Unsupported cipher: " << cipher << std::endl;
				return false;
			}
			set_config_value("cipher",json_obj["cipher"].get<std::string>());
		}
		else
		{
			set_config_value("cipher", std::string("aes-256-ofb"));
		}
		if (json_obj.find("timeout")!=json_obj.end())
		{
			int timeout = static_cast<int>(json_obj["timeout"]);
			set_config_value("timeout", timeout < 30 ? 30 : timeout);
		}
		else
		{
			set_config_value("timeout",240);
		}
		if (json_obj.find("workers")!=json_obj.end())
		{
			int threads = json_obj["workers"];
			set_config_value("workers", threads < 1 ? 1 : (threads > 16 ? 16 : threads));
		}
		else
		{
			set_config_value("workers",2);
		}
		if (json_obj.find("log_level") != json_obj.end())
		{
			set_config_value("log_level", int(spdlog::level::from_str(json_obj["log_level"])));
		}
		else
		{
			set_config_value("log_level", int(spdlog::level::level_enum::off));
		}
		rollback = false;
		return true;
	}
	std::string http_proxy_client_config::get_proxy_server_address() const
	{
		return this->get_config_value<std::string>("proxy_server_address");
	}

	int http_proxy_client_config::get_proxy_server_port() const
	{
		return this->get_config_value<int>("proxy_server_port");
	}

	std::string http_proxy_client_config::get_bind_address() const
	{
		return this->get_config_value<std::string>("bind_address");
	}

	int http_proxy_client_config::get_listen_port() const
	{
		return this->get_config_value<int>("listen_port");
	}

	std::string http_proxy_client_config::get_rsa_public_key() const
	{
		return this->get_config_value<std::string>("rsa_public_key");
	}

	std::string http_proxy_client_config::get_cipher() const
	{
		return this->get_config_value<std::string>("cipher");
	}

	int http_proxy_client_config::get_timeout() const
	{
		return this->get_config_value<int>("timeout");
	}

	int http_proxy_client_config::get_workers() const
	{
		return this->get_config_value<int>("workers");
	}

	http_proxy_client_config& http_proxy_client_config::get_instance()
	{
		static http_proxy_client_config instance;
		return instance;
	}
	spdlog::level::level_enum http_proxy_client_config::get_log_level() const
	{
		return spdlog::level::level_enum(this->get_config_value<int>("log_level"));
	}
} // namespace azure_proxy
