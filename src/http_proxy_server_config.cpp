/*
 *    http_proxy_server_config.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <memory>
#include <fstream>
#include <iostream>

#include "authentication.hpp"
#include "encrypt.hpp"
#include "http_proxy_server_config.hpp"

#include <nlohmann/json.hpp>
namespace azure_proxy {
	using json = nlohmann::json;
	using std::cerr;
http_proxy_server_config::http_proxy_server_config()
{
}
template<>
void http_proxy_server_config::set_config_value<int>(const std::string& key, int value)
{
	config_map_int[key] = value;
}
template<>
void http_proxy_server_config::set_config_value<std::string>(const std::string& key, std::string value)
{
	config_map_str[key] = value;
}
template<>
int http_proxy_server_config::get_config_value<int>(const std::string& key)const
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
std::string http_proxy_server_config::get_config_value<std::string>(const std::string& key)const
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
bool http_proxy_server_config::load_config(const std::string& config_filename)
{
	std::ifstream the_file(config_filename);
	std::string config_data((std::istreambuf_iterator<char>(the_file)), (std::istreambuf_iterator<char>()));
	bool rollback = true;
	std::shared_ptr<bool> auto_rollback(&rollback, [this](bool* rollback) {
		if (*rollback) {
			config_map_str.clear();
			config_map_int.clear();
			authentication::get_instance().remove_all_users();
		}
	});

	json json_obj(config_data);
	try
	{
		json_obj = json::parse(config_data);
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << "Failed to parse config" << std::endl;
		return false;
	}
	if (!json_obj.is_object())
	{
		std::cerr << "The data should be a map" << std::endl;
		return false;
	}
	if (json_obj.find("bind_address")!=json_obj.end()) {
		set_config_value("bind_address",json_obj["bind_address"].get<std::string>());
	}
	else {
		set_config_value("bind_address", std::string("0.0.0.0"));
	}
	if (json_obj.find("listen_port")!=json_obj.end()) {
		set_config_value("listen_port", json_obj["listen_port"].get<int>());
	}
	else {
		set_config_value("listen_port", 8090);
	}
	if (json_obj.find("rsa_private_key")==json_obj.end()) {
		std::cerr << "Could not find \"rsa_private_key\" in config or it's value is not a string" << std::endl;
		return false;
	}
	const std::string& rsa_private_key = json_obj["rsa_private_key"];
	try {
		rsa rsa_pri(rsa_private_key);
		if (rsa_pri.modulus_size() < 128) {
			std::cerr << "Must use RSA keys of at least 1024 bits" << std::endl;
			return false;
		}
	}
	catch (const std::exception&) {
		std::cerr << "The value of rsa_private_key is bad" << std::endl;
		return false;
	}
	set_config_value("rsa_private_key", rsa_private_key);
	if (json_obj.find("timeout")!=json_obj.end()) {
		int timeout = static_cast<int>(json_obj["timeout"]);
		set_config_value("timeout",timeout < 30 ? 30 : timeout);
	}
	else {
		set_config_value("timeout", 240);
	}
	if (json_obj.find("workers")!=json_obj.end()) {
		int threads = json_obj["workers"];
		set_config_value("workers",threads < 1 ? 1 : (threads > 16 ? 16 : threads));
	}
	else {
		set_config_value("workers", 4);
	}
	if (json_obj.find("auth")!=json_obj.end()) {
		if (json_obj["auth"].get<bool>())
		{
			set_config_value("auth", 1);
		}
		else
		{
			set_config_value("auth", 0);
		}
		if (json_obj.find("users")==json_obj.end()) {
			std::cerr << "Could not find \"users\" in config or it's value is not a array" << std::endl;
			return false;
		}
		json users_array = json_obj["users"];
		for (size_t i = 0; i < users_array.size(); ++i) {
			if (users_array[i].find("username")==users_array[i].end() || users_array[i].find("username")==users_array[i].end()) {
				std::cerr << "The value of \"users\" contains unexpected element" << std::endl;
				return false;
			}
			authentication::get_instance().add_user(users_array[i]["username"],users_array[i]["password"]);
		}
	}
	else {
		set_config_value("auth", 0);
	}

	rollback = false;
	return true;
}


std::string http_proxy_server_config::get_bind_address() const
{
	return this->get_config_value<std::string>("bind_address");
}

int http_proxy_server_config::get_listen_port() const
{
	return this->get_config_value<int>("listen_port");
}

std::string http_proxy_server_config::get_rsa_private_key() const
{
	return this->get_config_value<std::string>("rsa_private_key");
}

int http_proxy_server_config::get_timeout() const
{
	return this->get_config_value<int>("timeout");
}

int http_proxy_server_config::get_workers() const
{
	return this->get_config_value<int>("workers");
}

bool http_proxy_server_config::enable_auth() const
{
	return (this->get_config_value<int>("auth")!=0);
}

http_proxy_server_config& http_proxy_server_config::get_instance()
{
	static http_proxy_server_config instance;
	return instance;
}

} // namespace azure_proxy
