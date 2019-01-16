#include "http_header_parser.hpp"
#include <iostream>

using namespace azure_proxy;
using namespace std;
int main()
{
	std::string request_input = "CONNECT www.bing.com:443 HTTP/1.1\r\nHost: www.bing.com:443\r\nProxy-Connection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n\r\n";
	http_request_parser _parser;
	_parser.append_input(reinterpret_cast<const unsigned char*>(request_input.c_str()), request_input.size());
	auto parse_result = _parser.parse();
	if (parse_result.first != http_parser_result::read_one_header)
	{
		cout << "fail to parse content 111" << endl;
		return 1;
	}
	auto new_header = _parser._header.encode_to_data();
	cout << "new head is " << new_header << endl;
	_parser.reset();
	_parser.append_input(reinterpret_cast<const unsigned char*>(new_header.c_str()), new_header.size());
	parse_result = _parser.parse();
	if (parse_result.first != http_parser_result::read_one_header)
	{
		cout << "fail to parse content 222" << endl;
		return 1;
	}
	cout << "parse suc" << endl;
	return 1;
}