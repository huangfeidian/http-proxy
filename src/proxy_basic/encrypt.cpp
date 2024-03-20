#include "encrypt.hpp"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
namespace http_proxy
{
	void stream_encryptor::transform(unsigned char *data, std::size_t length, std::size_t block_size)
	{
		std::vector<unsigned char> temp_buffer(block_size, 0);
		for (std::size_t i = 0; i * block_size < length; i++)
		{
			std::size_t cur_block_size = block_size;
			if (length - i * block_size < block_size)
			{
				cur_block_size = length % block_size;
			}
			encrypt(data + i * block_size, &temp_buffer[0], cur_block_size);
			std::copy(&temp_buffer[0], &temp_buffer[0] + cur_block_size, data + i * block_size);
		}
	}

	aes_cfb128_encryptor::aes_cfb128_encryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_cfb128_encryptor::encrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_cfb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
	}

	aes_cfb128_decryptor::aes_cfb128_decryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_cfb128_decryptor::decrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_cfb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
	}

	aes_cfb8_encryptor::aes_cfb8_encryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_cfb8_encryptor::encrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_cfb8_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
	}

	aes_cfb8_decryptor::aes_cfb8_decryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_cfb8_decryptor::decrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_cfb8_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
	}

	aes_cfb1_encryptor::aes_cfb1_encryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_cfb1_encryptor::encrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_cfb1_encrypt(in, out, length * 8, &this->aes_ctx, this->ivec, &this->num, AES_ENCRYPT);
	}

	aes_cfb1_decryptor::aes_cfb1_decryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_cfb1_decryptor::decrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_cfb1_encrypt(in, out, length * 8, &this->aes_ctx, this->ivec, &this->num, AES_DECRYPT);
	}

	aes_ofb128_encryptor::aes_ofb128_encryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_ofb128_encryptor::encrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_ofb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num);
	}

	aes_ofb128_decryptor::aes_ofb128_decryptor(const unsigned char *key, std::uint32_t key_bits, unsigned char *ivec) : num(0)
	{
		assert(key && ivec);
		assert(key_bits == 128 || key_bits == 192 || key_bits == 256);
		std::memcpy(this->key, key, key_bits / 8);
		std::memcpy(this->ivec, ivec, sizeof(this->ivec));
		AES_set_encrypt_key(this->key, key_bits, &this->aes_ctx);
	}

	void aes_ofb128_decryptor::decrypt(const unsigned char *in, unsigned char *out, std::size_t length)
	{
		assert(in && out);
		AES_ofb128_encrypt(in, out, length, &this->aes_ctx, this->ivec, &this->num);
	}

	rsa::rsa(const std::string &key)
		: key_(key)
	{
		if (key.size() > 26 && std::equal(key.begin(), key.begin() + 26, "-----BEGIN PUBLIC KEY-----"))
		{
			this->is_pub = true;
		}
		else if (key.size() > 31 && std::equal(key.begin(), key.begin() + 31, "-----BEGIN RSA PRIVATE KEY-----"))
		{
			this->is_pub = false;
		}
		else
		{
			throw std::invalid_argument("invalid key content format key is:" + key_);
		}

		auto bio_handle = std::shared_ptr<BIO>(BIO_new_mem_buf(const_cast<char *>(key.data()), static_cast<int>(key.size())), BIO_free);
		if (bio_handle)
		{
			if (this->is_pub)
			{
				this->rsa_handle = std::shared_ptr<RSA>(PEM_read_bio_RSA_PUBKEY(bio_handle.get(), nullptr, nullptr, nullptr), RSA_free);
			}
			else
			{
				this->rsa_handle = std::shared_ptr<RSA>(PEM_read_bio_RSAPrivateKey(bio_handle.get(), nullptr, nullptr, nullptr), RSA_free);
			}
		}
		if (!this->rsa_handle)
		{
			throw std::invalid_argument("invalid argument");
		}
	}

	int rsa::encrypt(int flen, unsigned char *from, unsigned char *to, rsa_padding padding)
	{
		assert(from && to);
		int pad = this->rsa_padding2int(padding);
		if (this->is_pub)
		{
			return RSA_public_encrypt(flen, from, to, this->rsa_handle.get(), pad);
		}
		else
		{
			return RSA_private_encrypt(flen, from, to, this->rsa_handle.get(), pad);
		}
	}

	int rsa::decrypt(int flen, const unsigned char *from, unsigned char *to, rsa_padding padding)
	{
		assert(from && to);
		int pad = this->rsa_padding2int(padding);
		if (this->is_pub)
		{
			return RSA_private_decrypt(flen, from, to, this->rsa_handle.get(), pad);
		}
		else
		{
			return RSA_private_decrypt(flen, from, to, this->rsa_handle.get(), pad);
		}
	}

	int rsa::modulus_size() const
	{
		return RSA_size(this->rsa_handle.get());
	}

	bool aes_generator::generate(const std::string &cipher_name, char &cipher_code, std::vector<unsigned char> &ivec, std::vector<unsigned char> &key_vec, std::unique_ptr<stream_encryptor> &encryptor, std::unique_ptr<stream_decryptor> &decryptor)
	{
		assert(cipher_name[3] == '-' && cipher_name[7] == '-');
		if (std::strcmp(cipher_name.c_str() + 8, "cfb") == 0 || std::strcmp(cipher_name.c_str() + 8, "cfb128") == 0)
		{
			// where is cfb-128
			//  aes-xxx-cfb
			if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
			{
				cipher_code = 0x00;
				key_vec.resize(128 / 8);
			}
			else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
			{
				cipher_code = 0x05;
				key_vec.resize(192 / 8);
			}
			else
			{
				cipher_code = 0x0A;
				key_vec.resize(256 / 8);
			}
			key_generator::get_instance().generate(ivec.data(), ivec.size());
			key_generator::get_instance().generate(key_vec.data(), key_vec.size());
			encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb128_encryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb128_decryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			return true;
		}
		else if (std::strcmp(cipher_name.c_str() + 8, "cfb8") == 0)
		{
			// aes-xxx-cfb8
			if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
			{
				cipher_code = 0x01;
				key_vec.resize(128 / 8);
			}
			else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
			{
				cipher_code = 0x06;
				key_vec.resize(192 / 8);
			}
			else
			{
				cipher_code = 0x0B;
				key_vec.resize(256 / 8);
			}
			key_generator::get_instance().generate(ivec.data(), ivec.size());
			key_generator::get_instance().generate(key_vec.data(), key_vec.size());
			encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb8_encryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb8_decryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			return true;
		}
		else if (std::strcmp(cipher_name.c_str() + 8, "cfb1") == 0)
		{
			// aes-xxx-cfb1
			if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
			{
				cipher_code = 0x02;
				key_vec.resize(128 / 8);
			}
			else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
			{
				cipher_code = 0x07;
				key_vec.resize(192 / 8);
			}
			else
			{
				cipher_code = 0x0C;
				key_vec.resize(256 / 8);
			}
			key_generator::get_instance().generate(ivec.data(), ivec.size());
			key_generator::get_instance().generate(key_vec.data(), key_vec.size());
			encryptor = std::unique_ptr<stream_encryptor>(new aes_cfb1_encryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			decryptor = std::unique_ptr<stream_decryptor>(new aes_cfb1_decryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			return true;
		}
		else if (std::strcmp(cipher_name.c_str() + 8, "ofb") == 0)
		{
			// aes-xxx-ofb
			if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
			{
				cipher_code = 0x03;
				key_vec.resize(128 / 8);
			}
			else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
			{
				cipher_code = 0x08;
				key_vec.resize(192 / 8);
			}
			else
			{
				cipher_code = 0x0D;
				key_vec.resize(256 / 8);
			}
			key_generator::get_instance().generate(ivec.data(), ivec.size());
			key_generator::get_instance().generate(key_vec.data(), key_vec.size());
			encryptor = std::unique_ptr<stream_encryptor>(new aes_ofb128_encryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			decryptor = std::unique_ptr<stream_decryptor>(new aes_ofb128_decryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
			return true;
		}
		// else if (std::strcmp(cipher_name.c_str() + 8, "ctr") == 0)
		// {
		// 	// aes-xxx-ctr
		// 	if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "128"))
		// 	{
		// 		cipher_code = 0x04;
		// 		key_vec.resize(128 / 8);
		// 	}
		// 	else if (std::equal(cipher_name.begin() + 4, cipher_name.begin() + 7, "192"))
		// 	{
		// 		cipher_code = 0x09;
		// 		key_vec.resize(192 / 8);
		// 	}
		// 	else
		// 	{
		// 		cipher_code = 0x0E;
		// 		key_vec.resize(256 / 8);
		// 	}
		// 	std::fill(ivec.begin(), ivec.end(), 0);
		// 	key_generator::get_instance().generate(key_vec.data(), key_vec.size());
		// 	this->encryptor = std::unique_ptr<stream_encryptor>(new aes_ctr128_encryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
		// 	this->decryptor = std::unique_ptr<stream_decryptor>(new aes_ctr128_decryptor(key_vec.data(), static_cast<std::uint32_t>(key_vec.size() * 8), ivec.data()));
		// }
		// 7 ~ 22 ivec
		// 23 ~ key
		return false;
	}
}
#pragma GCC diagnostic pop