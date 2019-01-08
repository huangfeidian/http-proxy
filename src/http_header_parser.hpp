﻿/*
 *    http_header_parser.hpp:
 *
 *    Copyright (C) 2013-2015 limhiaoing <blog.poxiao.me> All Rights Reserved.
 *
 */

#ifndef AZURE_HTTP_HEADER_PARSER_HPP
#define AZURE_HTTP_HEADER_PARSER_HPP

#include <algorithm>
#include <cctype>
#include <map>
#include <string>

namespace azure_proxy
{

	struct default_filed_name_compare
	{
		bool operator() (const std::string& str1, const std::string& str2) const
		{
			return std::lexicographical_compare(str1.begin(), str1.end(), str2.begin(), str2.end(), [](const char ch1, const char ch2) -> bool
			{
				return std::tolower(static_cast<unsigned char>(ch1)) < std::tolower(static_cast<unsigned char>(ch2));
			});
		}
	};

	// https://stackoverflow.com/questions/4371328/are-duplicate-http-response-headersacceptable
	//Cache-Control: no-cache
	//Cache-Control: no - store
	// 因为http头里面会有重复的key 所以这里只能用multimap
	typedef std::multimap<const std::string, std::string, default_filed_name_compare> http_headers_container;

	class http_request_header
	{
		friend class http_header_parser;
		std::string _method;
		std::string _scheme;
		std::string _host;
		unsigned short _port;
		std::string _path_and_query;
		std::string _http_version;
		std::string header_counter;
		http_headers_container _headers_map;
		http_request_header();
	public:
		const std::string& method() const;
		const std::string& scheme() const;
		const std::string& host() const;
		unsigned short port() const;
		const std::string& path_and_query() const;
		const std::string& http_version() const;
		std::unique_ptr<std::string> get_header_value(const std::string& name) const;
		std::size_t erase_header(const std::string& name);
		const http_headers_container& get_headers_map() const;
		std::string get_header_counter() const;
		void set_header_counter(const std::string& counter);
	};

	class http_response_header
	{
		friend class http_header_parser;
		std::string _http_version;
		unsigned int _status_code;
		std::string _status_description;
		http_headers_container _headers_map;
		std::string header_counter;
		http_response_header();
	public:
		const std::string& http_version() const;
		unsigned int status_code() const;
		const std::string& status_description() const;
		std::unique_ptr<std::string> get_header_value(const std::string& name) const;
		std::size_t erase_header(const std::string& name);
		const http_headers_container& get_headers_map() const;
		std::string get_header_counter() const;
	};

	class http_header_parser
	{
		static http_headers_container parse_headers(std::string::const_iterator begin, std::string::const_iterator end);
	public:
		static std::unique_ptr<http_request_header> parse_request_header(std::string::const_iterator begin, std::string::const_iterator end);
		static std::unique_ptr<http_response_header> parse_response_header(std::string::const_iterator begin, std::string::const_iterator end);
	};
	void string_to_lower_case(std::string& str);
	std::string remove_trail_blank(const std::string& input);

}; // namespace azure_proxy

#endif
