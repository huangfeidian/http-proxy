﻿/*
 *    http_header_parser.cpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#include <iterator>
#include <regex>
#include <memory>
#include <assert.h>
#include <unordered_set>
#include "http_header_parser.hpp"

namespace azure_proxy
{
	const int tokens[128] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
	};
	std::unordered_set<std::string> valid_request_method = { "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT" };

	std::string remove_trail_blank(const std::string& input)
	{
		size_t idx = input.size();
		for (; idx > 0; idx++)
		{
			if (input[idx - 1] == ' ' || input[idx - 1] ==
				'\t')

			{
				continue;
			}
			else
			{
				break;
			}
		}
		if (idx == 0)
		{
			return std::string();
		}
		return input.substr(0, idx);
	}
	void string_to_lower_case(std::string& str)
	{
		for (auto iter = str.begin(); iter != str.end(); ++iter)
		{
			*iter = std::tolower(static_cast<unsigned char>(*iter));
		}
	}
	void http_request_header::reset()
	{
		_method.clear();
		_scheme.clear();
		_host.clear();
		_path_and_query.clear();
		_port = 0;
		_http_version.clear();
		header_counter.clear();
		_proxy_authorization.clear();
		_proxy_connection.clear();
		_headers_map.clear();
	}
	http_request_header::http_request_header() : _port(80)
	{
	}

	const std::string& http_request_header::method() const
	{
		return this->_method;
	}

	const std::string& http_request_header::scheme() const
	{
		return this->_scheme;
	}

	const std::string& http_request_header::host() const
	{
		return this->_host;
	}

	unsigned short http_request_header::port() const
	{
		return this->_port;
	}

	const std::string& http_request_header::path_and_query() const
	{
		return this->_path_and_query;
	}

	const std::string& http_request_header::http_version() const
	{
		return this->_http_version;
	}
	const std::string& http_request_header::get_header_counter() const
	{
		return header_counter;
	}
	const std::string& http_request_header::proxy_authorization() const
	{
		return _proxy_authorization;
	}
	const std::string& http_request_header::proxy_connection() const
	{
		return _proxy_connection;
	}
	void http_request_header::set_header_counter(const std::string& counter)
	{
		header_counter = counter;
	}
	bool http_request_header::valid_method() const
	{
		if (valid_request_method.find(_method) == valid_request_method.end())
		{
			return false;
		}
		else
		{
			return true;
		}

	}
	bool http_request_header::valid_version() const
	{
		return _http_version == "1.1" || _http_version == "1.0";
	}
	std::string http_request_header::encode_to_data() const
	{
		std::string result;
		result.reserve(500);
		result += _method;
		result += " ";
		result += _path_and_query;
		result += " HTTP/";
		result += _http_version;
		result += "\r\n";
		for (const auto& header : _headers_map)
		{
			result += std::get<0>(header);
			result += ": ";
			result += std::get<1>(header);
			result += "\r\n";
		}
		result += "\r\n";
		return result;

	}
	std::unique_ptr<std::string> http_request_header::get_header_value(const std::string& name) const
	{
		auto iter = this->_headers_map.find(name);
		if (iter == this->_headers_map.end())
		{
			return nullptr;
		}
		return std::make_unique<std::string>(iter->second);
	}

	std::size_t http_request_header::erase_header(const std::string& name)
	{
		return this->_headers_map.erase(name);
	}

	const http_headers_container& http_request_header::get_headers_map() const
	{
		return this->_headers_map;
	}

	http_response_header::http_response_header()
	{
	}
	void http_response_header::reset()
	{
		_http_version.clear();
		_status_code = 0;
		_status_description.clear();
		_headers_map.clear();
		header_counter.clear();

	}

	const std::string& http_response_header::http_version() const
	{
		return this->_http_version;
	}

	unsigned int http_response_header::status_code() const
	{
		return this->_status_code;
	}

	const std::string& http_response_header::status_description() const
	{
		return this->_status_description;
	}

	std::unique_ptr<std::string> http_response_header::get_header_value(const std::string& name) const
	{
		auto iter = this->_headers_map.find(name);
		if (iter == this->_headers_map.end())
		{
			return nullptr;
		}
		return std::make_unique<std::string>(iter->second);
	}

	std::size_t http_response_header::erase_header(const std::string& name)
	{
		return this->_headers_map.erase(name);
	}

	const http_headers_container& http_response_header::get_headers_map() const
	{
		return this->_headers_map;
	}
	const std::string& http_response_header::get_header_counter() const
	{
		return header_counter;
	}
	bool http_response_header::valid_status() const
	{
		return _status_code >= 100 && _status_code <= 700;
	}
	bool http_response_header::valid_version() const
	{
		if (_http_version != "1.0" && _http_version != "1.1")
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	std::string http_response_header::encode_to_data() const
	{
		std::string result;
		result.reserve(500);
		result += "HTTP/";
		result += _http_version;
		result.push_back(' ');
		result += std::to_string(_status_code);
		if (!_status_description.empty())
		{
			result.push_back(' ');
			result += _status_description;
		}
		result += "\r\n";

		for (const auto& header : _headers_map)
		{
			result += std::get<0>(header);
			result += ": ";
			result += std::get<1>(header);
			result += "\r\n";
		}
		result += "\r\n";
		return result;
	}


	http_headers_container http_header_parser::parse_headers(std::string::const_iterator begin, std::string::const_iterator end)
	{
		http_headers_container headers;
		auto result = parse_headers(static_cast<const unsigned char*>(begin), static_cast<const unsigned char*>(end), headers);
		if (result.first != http_parser_result::read_one_header)
		{
			headers.clear();
			return headers;
		}
		return headers;
	}
	std::pair<http_parser_result, std::uint32_t> parse_headers(const unsigned char* begin, const unsigned char* end, http_headers_container& headers)
	{
		static uint32_t header_counter = 0;
		//lambdas are inlined  don't worry be happy
		auto is_token_char = [](char ch) -> bool
		{
			if (ch >= 128)
			{
				return false;
			}
			return tokens[ch];
		};

		enum class parse_header_state
		{
			header_field_name_start,
			header_field_name,
			header_field_value_left_ows,
			header_field_value,
			header_field_cr,
			header_field_crlf,
			header_field_crlfcr,
			header_compelete,
			header_parse_failed
		};

		parse_header_state state = parse_header_state::header_field_name_start;
		std::string header_field_name;
		std::string header_field_value;
		//哈哈一个状态机，不过模拟的不彻底啊，话说这位同学为什么这么喜欢字节流的状态机呢 
		//应该是网络流并不是一次传输完成的 只有字节流的边界是清晰的
		auto iter = begin;
		for (; iter != end && state != parse_header_state::header_compelete && state != parse_header_state::header_parse_failed; ++iter)
		{
			switch (state)
			{
			case parse_header_state::header_field_name_start:
				if (is_token_char(*iter))
				{
					header_field_name.push_back(*iter);
					state = parse_header_state::header_field_name;
				}
				else
				{
					if (iter == begin && *iter == '\r')
					{
						state = parse_header_state::header_field_crlfcr;
					}
					else
					{
						state = parse_header_state::header_parse_failed;
					}
				}
				break;
			case parse_header_state::header_field_name:
				if (is_token_char(*iter))
				{
					header_field_name.push_back(*iter);
				}
				else
				{
					if (*iter == ':')
					{
						state = parse_header_state::header_field_value_left_ows;
					}
					else
					{
						state = parse_header_state::header_parse_failed;
					}
				}
				break;
			case parse_header_state::header_field_value_left_ows:
				if (*iter == ' ' || *iter == '\t')
				{
					continue;
				}
				else
				{
					if (*iter == '\r')
					{
						state = parse_header_state::header_field_cr;
					}
					else
					{
						header_field_value.push_back(*iter);
						state = parse_header_state::header_field_value;
					}
				}
				break;
			case parse_header_state::header_field_value:
				if (*iter == '\r')
				{
					state = parse_header_state::header_field_cr;
				}
				else
				{
					header_field_value.push_back(*iter);
				}
				break;
			case parse_header_state::header_field_cr:
				if (*iter == '\n')
				{
					state = parse_header_state::header_field_crlf;
				}
				else
				{
					state = parse_header_state::header_parse_failed;
				}
				break;
			case parse_header_state::header_field_crlf:
				if (*iter == ' ' || *iter == '\t')
				{
					header_field_value.push_back(*iter);
					state = parse_header_state::header_field_value;
				}
				else
				{
					//删掉末尾的空白字符
					headers.insert(std::make_pair(std::move(header_field_name), std::move(remove_trail_blank(header_field_value))));
					if (*iter == '\r')
					{
						state = parse_header_state::header_field_crlfcr;
					}
					else
					{
						if (is_token_char(*iter))
						{
							header_field_name.push_back(*iter);
							state = parse_header_state::header_field_name;
						}
						else
						{
							state = parse_header_state::header_parse_failed;
						}
					}
				}
				break;
			case parse_header_state::header_field_crlfcr:
				if (*iter == '\n')
				{
					state = parse_header_state::header_compelete;
				}
				break;
			default:
				assert(false);
			}
		}
		if (state != parse_header_state::header_compelete)
		{
			return std::make_pair(http_parser_result::buffer_overflow, 0);
		}
		headers.insert(std::make_pair("header_counter", std::to_string(header_counter++)));
		return std::make_pair(http_parser_result::read_one_header, iter - begin);
	}
	std::unique_ptr<http_request_header> http_header_parser::parse_request_header(std::string::const_iterator begin, std::string::const_iterator end)
	{
		auto iter = begin;
		auto tmp = iter;
		for (; iter != end && *iter != ' ' && *iter != '\r'; ++iter)
		{
			//get the method
		}
		if (iter == tmp || iter == end || *iter != ' ')
		{
			return nullptr;
		}
		http_request_header header;
		header._method = std::string(tmp, iter);
		tmp = ++iter;
		for (; iter != end && *iter != ' ' && *iter != '\r'; ++iter)
		{
			//get  the url
		}
		if (iter == tmp || iter == end || *iter != ' ')
		{
			return nullptr;
		}
		auto request_uri = std::string(tmp, iter);
		if (header.method() == "CONNECT")
		{
			std::regex regex("(.+?):(\\d+)"); //host:port
			std::match_results<std::string::iterator> match_results;
			if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex))
			{
				return nullptr;
			}
			header._host = match_results[1];
			try
			{
				header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[2])));
			}
			catch (const std::exception&)
			{
				return nullptr;
			}
		}
		else
		{
			std::regex regex("(.+?)://(.+?)(:(\\d+))?(/.*)"); //GET http://download.microtool.de:80/somedata.exe
			std::match_results<std::string::iterator> match_results;
			if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex))
			{
				return nullptr;
			}
			header._scheme = match_results[1];
			header._host = match_results[2];
			if (match_results[4].matched)
			{
				try
				{
					header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[4])));
				}
				catch (const std::exception&)
				{
					return nullptr;
				}
			}
			header._path_and_query = match_results[5];
		}

		tmp = ++iter;
		for (; iter != end && *iter != '\r'; ++iter)
		{
			//to the end of line 
		}
		// HTTP/x.y
		if (iter == end || std::distance(tmp, iter) < 6 || !std::equal(tmp, tmp + 5, "HTTP/"))
		{
			return nullptr;
		}

		header._http_version = std::string(tmp + 5, iter);

		++iter;
		if (iter == end || *iter != '\n')
		{
			return nullptr;
		}

		++iter;
		try
		{
			header._headers_map = parse_headers(iter, end);
			auto temp_iter = header._headers_map.find("header_counter");
			if (temp_iter != header._headers_map.end())
			{
				header.header_counter = temp_iter->second;
				header._headers_map.erase("header_counter");
			}
			temp_iter = header._headers_map.find("Proxy-Connection");
			if (temp_iter != header._headers_map.end())
			{
				header._proxy_connection = temp_iter->second;
				header._headers_map.erase("Proxy-Connection");
			}
			temp_iter = header._headers_map.find("Proxy-Authorization");
			if (temp_iter != header._headers_map.end())
			{
				header._proxy_authorization = temp_iter->second;
				header._headers_map.erase("Proxy-Authorization");
			}
		}
		catch (const std::exception&)
		{
			return nullptr;
		}

		return std::make_unique<http_request_header>(header);
	}

	std::unique_ptr<http_response_header> http_header_parser::parse_response_header(std::string::const_iterator begin, std::string::const_iterator end)
	{
		auto iter = begin;
		auto tmp = iter;
		for (; iter != end && *iter != ' ' && *iter != '\r'; ++iter)
		{
			// to the end of line
		}
		if (std::distance(tmp, iter) < 6 || iter == end || *iter != ' ' || !std::equal(tmp, tmp + 5, "HTTP/")) return nullptr;
		http_response_header header;
		header._http_version = std::string(tmp + 5, iter);
		tmp = ++iter;
		for (; iter != end && *iter != ' ' && *iter != '\r'; ++iter)
		{

		}
		if (tmp == iter || iter == end)
		{
			return nullptr;
		}
		try
		{
			header._status_code = std::stoul(std::string(tmp, iter));
		}
		catch (const std::exception&)
		{
			return nullptr;
		}

		if (*iter == ' ')
		{
			tmp = ++iter;
			for (; iter != end && *iter != '\r'; ++iter)
			{

			}
			if (iter == end || *iter != '\r')
			{
				return nullptr;
			}
			header._status_description = std::string(tmp, iter);
		}

		if (*iter != '\r')
		{
			return nullptr;
		}

		if (iter == end || *(++iter) != '\n')
		{
			return nullptr;
		}

		++iter;
		try
		{
			header._headers_map = parse_headers(iter, end);
			auto counter_iter = header._headers_map.find("header_counter");
			if (counter_iter != header._headers_map.end())
			{
				header.header_counter = counter_iter->second;
				header._headers_map.erase("header_counter");
			}
		}
		catch (const std::exception&)
		{
			return nullptr;
		}

		return std::make_unique<http_response_header>(header);
	}
	http_parser_result http_header_parser::parse_request_header(const unsigned char* begin, const unsigned char* end, http_request_header& header)
	{

		auto iter = begin;
		auto tmp = iter;
		for (; iter != end && *iter != ' ' && *iter != '\r'; ++iter)
		{
			//get the method
		}
		if (iter == tmp || iter == end || *iter != ' ')
		{
			return http_parser_result::buffer_overflow;
		}
		http_request_header header;
		header._method = std::string(tmp, iter);
		tmp = ++iter;
		for (; iter != end && *iter != ' ' && *iter != '\r'; ++iter)
		{
			//get  the url
		}
		if (iter == tmp || iter == end || *iter != ' ')
		{
			return http_parser_result::buffer_overflow;
		}
		auto request_uri = std::string(tmp, iter);
		if (header.method() == "CONNECT")
		{
			std::regex regex("(.+?):(\\d+)"); //host:port
			std::match_results<std::string::iterator> match_results;
			if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex))
			{
				return http_parser_result::buffer_overflow;
			}
			header._host = match_results[1];
			try
			{
				header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[2])));
			}
			catch (const std::exception&)
			{
				return http_parser_result::buffer_overflow;
			}
		}
		else
		{
			std::regex regex("(.+?)://(.+?)(:(\\d+))?(/.*)"); //GET http://download.microtool.de:80/somedata.exe
			std::match_results<std::string::iterator> match_results;
			if (!std::regex_match(request_uri.begin(), request_uri.end(), match_results, regex))
			{
				return http_parser_result::buffer_overflow;
			}
			header._scheme = match_results[1];
			header._host = match_results[2];
			if (match_results[4].matched)
			{
				try
				{
					header._port = static_cast<unsigned short>(std::stoul(std::string(match_results[4])));
				}
				catch (const std::exception&)
				{
					return http_parser_result::buffer_overflow;
				}
			}
			header._path_and_query = match_results[5];
		}

		tmp = ++iter;
		for (; iter != end && *iter != '\r'; ++iter)
		{
			//to the end of line 
		}
		// HTTP/x.y
		if (iter == end || std::distance(tmp, iter) < 6 || !std::equal(tmp, tmp + 5, "HTTP/"))
		{
			return http_parser_result::buffer_overflow;
		}

		header._http_version = std::string(tmp + 5, iter);

		++iter;
		if (iter == end || *iter != '\n')
		{
			return http_parser_result::buffer_overflow;
		}

		++iter;
		try
		{
			header._headers_map = parse_headers(iter, end);
			auto temp_iter = header._headers_map.find("header_counter");
			if (temp_iter != header._headers_map.end())
			{
				header.header_counter = temp_iter->second;
				header._headers_map.erase("header_counter");
			}
			temp_iter = header._headers_map.find("Proxy-Connection");
			if (temp_iter != header._headers_map.end())
			{
				header._proxy_connection = temp_iter->second;
				header._headers_map.erase("Proxy-Connection");
			}
			temp_iter = header._headers_map.find("Proxy-Authorization");
			if (temp_iter != header._headers_map.end())
			{
				header._proxy_authorization = temp_iter->second;
				header._headers_map.erase("Proxy-Authorization");
			}
		}
		catch (const std::exception&)
		{
			return http_parser_result::buffer_overflow;
		}

		return http_parser_result::read_one_header;
	}

	http_request_parser::http_request_parser()
	{
		buffer_size = 0;
		parser_idx = 0;
		_status = http_parser_status::read_header;
	}
	http_parser_result http_request_parser:: parse(const unsigned char* in_bytes, std::size_t length)
	{
		if (length + buffer_size >= MAX_REQUEST_HEADER_LENGTH)
		{
			return http_parser_result::buffer_overflow;
		}
		std::copy(in_bytes, in_bytes + length, buffer + buffer_size);
		buffer_size = buffer_size + length;
		std::uint32_t double_crlf_pos = buffer_size;
		if (_status == http_parser_status::read_header)
		{
			for (int i = 0; i < buffer_size - 4; i++)
			{
				if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
				{
					double_crlf_pos = i;
					break;
				}
			}
			if (double_crlf_pos == buffer_size)
			{
				return http_parser_result::reading_header;
			}

		}
	}

}; // namespace azure_proxy
