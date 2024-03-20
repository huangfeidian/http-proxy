#include "http_header_parser.hpp"
#include "encrypt.hpp"

#include <iostream>
#include <vector>

using namespace http_proxy;
using namespace std;

vector<string> get_request_test_cases()
{
	vector<string> result;
	result.push_back(string("GET http://www.baidu.com/ HTTP/1.1\r\nHost: www.baidu.com\r\nProxy-Connection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n\r\n"));

	result.push_back(string("CONNECT www.bing.com:443 HTTP/1.1\r\nHost: www.bing.com:443\r\nProxy-Connection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n\r\n"));
	result.push_back("GET http://192.168.1.69:9091/favicon.ico HTTP/1.1\r\nHost:192.168.1.69:9091\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n\r\n");
	return result;
}
vector<string> get_response_test_cases()
{
	vector<string> result;
	result.push_back(string("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 31\r\nContent-Type: text/html; charset=ISO-8859-1\r\nDate: Wed, 16 Jan 2019 15:45:53 GMT\r\nLocation:/transmission/web/\r\nServer: Transmission\r\n\r\n"));
	return result;
}
template <typename T>
bool http_request_test(const vector<string>& test_cases)
{
	T _parser;
	for (const auto& request_input : test_cases)
	{
		cout << "try parse " << request_input << endl;
		_parser.append_input(reinterpret_cast<const unsigned char*>(request_input.c_str()), request_input.size());
		auto parse_result = _parser.parse();
		if (parse_result.first != http_parser_result::read_one_header)
		{
			cout << "fail to parse content 111" << endl;
			return false;
		}
		auto new_header = _parser._header.encode_to_data();
		cout << "new head is " << new_header << endl;
		_parser.reset();
		_parser.append_input(reinterpret_cast<const unsigned char*>(new_header.c_str()), new_header.size());
		parse_result = _parser.parse();
		if (parse_result.first != http_parser_result::read_one_header)
		{
			cout << "fail to parse content 222" << endl;
			return false;
		}
		new_header = _parser._header.encode_to_data();
		cout << "new head is " << new_header << endl;
	}

	cout << "request parse suc" << endl;
	return true;
}
bool encrypt_decrypt_test(unique_ptr< stream_encryptor>& encryptor, unique_ptr<stream_decryptor>& decryptor, const vector<string>& test_cases)
{
	unsigned char buffer_1[65536];
	unsigned char buffer_2[65536];
	for (const string& one_case : test_cases)
	{
		encryptor->encrypt(reinterpret_cast<const unsigned char*>(one_case.c_str()), buffer_1, one_case.size());
		decryptor->decrypt(buffer_1, buffer_2, one_case.size());
		auto temp_string_view = string_view(reinterpret_cast<const char*>(buffer_2), one_case.size());
		if (temp_string_view != string_view(one_case))
		{
			cout << "fail to encrypt_decrypt_test 111" << one_case << endl;
			return false;
		}
	}
	for (const string& one_case : test_cases)
	{
		encryptor->copy(reinterpret_cast<const unsigned char*>(one_case.c_str()), buffer_1, one_case.size());
		encryptor->transform(buffer_1, one_case.size(), 64);
		decryptor->decrypt(buffer_1, buffer_2, one_case.size());
		auto temp_string_view = string_view(reinterpret_cast<const char*>(buffer_2), one_case.size());
		if (temp_string_view != string_view(one_case))
		{
			cout << "fail to encrypt_decrypt_test 222" << one_case << endl;
			return false;
		}
	}
	return true;
}
void test_cipher(const string cipher_name, const vector<string>& test_cases)
{
	unique_ptr< stream_encryptor> encryptor;
	unique_ptr<stream_decryptor> decryptor;
	char cipher_code = 0;
	std::vector<unsigned char> ivec(16);
	std::vector<unsigned char> key_vec;
	aes_generator::generate(cipher_name, cipher_code, ivec, key_vec, encryptor, decryptor);
	if (!encrypt_decrypt_test(encryptor, decryptor, test_cases))
	{
		cout << "fail to test_cipher " << cipher_name << endl;
	}
	else
	{
		cout << "test cipher " << cipher_name << " suc" << endl;
	}

}
int main()
{
	test_cipher("aes-256-ofb", get_request_test_cases());
}