#include "http_header_parser.hpp"
#include <iostream>
#include <vector>

using namespace azure_proxy;
using namespace std;

vector<string> get_test_cases()
{
	vector<string> result;
	result.push_back(string("GET http://www.baidu.com/ HTTP/1.1\r\nHost: www.baidu.com\r\nProxy-Connection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n\r\n"));

	//result.push_back(string("CONNECT www.bing.com:443 HTTP/1.1\r\nHost: www.bing.com:443\r\nProxy-Connection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n\r\n"));
	return result;
}
int main()
{
	http_request_parser _parser;
	for (const auto& request_input : get_test_cases())
	{
		cout << "try parse " << request_input << endl;
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
		new_header = _parser._header.encode_to_data();
		cout << "new head is " << new_header << endl;
	}
	
	cout << "parse suc" << endl;
	return 1;
}