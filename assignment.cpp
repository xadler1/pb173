#include <iostream>
#include <fstream>
#include <vector>
#include <dlfcn.h>
#include <string>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <memory>
#include "types.hpp"

int encrypt(char *keyarg, char *vecarg, const std::string &inputPath, const std::string &outputPath, void *lib)
{
	/* encrypt */
	mbedtls_aes_context aes;
	unsigned char key[16];
	unsigned char iv[16];

	for (size_t i = 0; i < 16; ++i) {
		key[i] = keyarg[i];
		iv[i] = vecarg[i];
	}

	std::vector<unsigned char> input;
	size_t input_len = 0;

	// library loading
	typedef int (*aes_setkey_enc_t)(mbedtls_aes_context *, const unsigned char *, unsigned int);
	typedef int (*aes_crypt_cbc_t)(mbedtls_aes_context *, int, size_t, unsigned char[], const unsigned char *, unsigned char *);

	aes_setkey_enc_t aes_setkey_enc = reinterpret_cast<aes_setkey_enc_t>(dlsym(lib, "mbedtls_aes_setkey_enc"));
	if (!aes_setkey_enc) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}

	aes_crypt_cbc_t aes_crypt_cbc = reinterpret_cast<aes_crypt_cbc_t>(dlsym(lib, "mbedtls_aes_crypt_cbc"));
	if (!aes_crypt_cbc) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}

	std::fstream fin(inputPath, std::ios::in);
	std::fstream fout(outputPath, std::ios::out);

	while (!fin.eof()) {
		++input_len;
		input.push_back(fin.get());
	}

	// remove eof character
	--input_len;
	input.pop_back();

	// padding
	size_t pad = input_len % 16;
	//std::cout << "input_len = " << input_len << std::endl;
	//std::cout << "pad = " << pad << std::endl;

	for (size_t i = pad; i < 16; ++i) {
		++input_len;
		input.push_back(16 - pad);

	}

	unsigned char* in = &input[0];
	auto output = std::make_unique<unsigned char[]>(input_len);

	aes_setkey_enc(&aes, key, 128);
	aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input_len, iv, in, output.get());

	fout.write(reinterpret_cast<char *> (&output[0]), input_len);

	/* hashing */
	typedef int (*sha512_t)(const unsigned char *, size_t, unsigned char[], int);
	sha512_t sha512 = reinterpret_cast<sha512_t>(dlsym(lib, "mbedtls_sha512_ret"));
	if (!sha512) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}

	std::fstream fouthash(outputPath + ".digest", std::ios::out);

	unsigned char hash[64];
	const unsigned char *hash_in = const_cast<const unsigned char *>(output.get());

	sha512(hash_in, input_len, hash, 0);

	fouthash << std::hex;

	for (size_t i = 0; i < 64; ++i) {
		fouthash << std::setfill('0') << std::setw(2) << static_cast<unsigned>(hash[i]);
	}

	fouthash << std::dec << std::endl;
	return 0;
}

int decrypt(char *keyarg, char *vecarg, const std::string &inputPath, const std::string &outputPath, void *lib)
{
	/* hashing */
	typedef int (*sha512_t)(const unsigned char *, size_t, unsigned char[], int);
	sha512_t sha512 = reinterpret_cast<sha512_t>(dlsym(lib, "mbedtls_sha512_ret"));
	if (!sha512) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}

	std::vector<unsigned char> input;
	size_t input_len = 0;

	std::fstream fin(inputPath, std::ios::in);
	std::fstream fout(outputPath, std::ios::out);

	while (!fin.eof()) {
		++input_len;
		input.push_back(fin.get());
	}

	// last iteration did not add any characters
	--input_len;

	unsigned char* in = &input[0];


	/* hash comparison */
	unsigned char hash[64];
	const unsigned char *hash_in = const_cast<const unsigned char *>(in);

	sha512(hash_in, input_len, hash, 0);

	std::stringstream computed;
	std::stringstream supplied;

	computed << std::hex;

	for (size_t i = 0; i < 64; ++i) {
		computed << std::setfill('0') << std::setw(2) << static_cast<unsigned>(hash[i]);
	}

	computed << std::dec << std::endl;

	std::fstream finhash(inputPath + ".digest", std::ios::in);

	while (!finhash.eof()) {
		supplied << static_cast<char>(finhash.get());
	}

	// remove eof character
	std::string sup = supplied.str();
	sup.pop_back();


	if (computed.str() != sup) {
		std::cerr << "digests don't match" << std::endl;
	}

	//std::cout << "computed = " << computed.str() << std::endl;
	//std::cout << "supplied = " << sup << std::endl;
	//std::cout << "computed size = " << computed.str().length() << std::endl;
	//std::cout << "supplied size = " << sup.length() << std::endl;

	//std::cout << input_len << std::endl;

	/* decrypting */
	mbedtls_aes_context aes;
	unsigned char key[16];
	unsigned char iv[16];

	for (size_t i = 0; i < 16; ++i) {
		key[i] = keyarg[i];
		iv[i] = vecarg[i];
	}

	typedef int (*aes_setkey_dec_t)(mbedtls_aes_context *, const unsigned char *, unsigned int);
	typedef int (*aes_crypt_cbc_t)(mbedtls_aes_context *, int, size_t, unsigned char[], const unsigned char *, unsigned char *);

	aes_setkey_dec_t aes_setkey_dec = reinterpret_cast<aes_setkey_dec_t>(dlsym(lib, "mbedtls_aes_setkey_dec"));
	if (!aes_setkey_dec) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}

	aes_crypt_cbc_t aes_crypt_cbc = reinterpret_cast<aes_crypt_cbc_t>(dlsym(lib, "mbedtls_aes_crypt_cbc"));
	if (!aes_crypt_cbc) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}



	auto output = std::make_unique<unsigned char[]>(input_len);

	//std::cout << "input_len = " << input_len << std::endl;

	aes_setkey_dec(&aes, key, 128);
	aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, iv, in, output.get());

	// remove padding
	size_t pad = output[input_len - 1];

	for (size_t i = 0; i < input_len - pad; ++i) {
		fout << output[i];
	}

	//printHash(output, input_len);


	return 0;
}

void printHelp()
{
	std::cout << "usage: assignment -en <key> <vector> <input file> <output file>" << std::endl;
	std::cout << "\t\tencrypts <input file> into <output file> and writes sha512 checksum into <output file>.digest" << std::endl;
	std::cout << "\t\t<key> must be 16 characters long" << std::endl;
	std::cout << "\t\t<vector> must be 16 characters long" << std::endl;
	std::cout << std::endl;
	std::cout << "       assignment -de <key> <vector> <input file> <output file>" << std::endl;
	std::cout << "\t\tdecrypts <input file> into <output file> and compare checksum with <input file>.digest" << std::endl;
	std::cout << "\t\t<key> must be 16 characters long" << std::endl;
	std::cout << "\t\t<vector> must be 16 characters long" << std::endl;
}

int main(int argc, char** argv)
{
	if (argc != 6) {
		printHelp();
		return 1;
	}

	// test wether library is present
	void *lib = dlopen("../libs/libmbedcrypto.so", RTLD_LAZY);

	if (!lib) {
		std::cerr << dlerror();
		return 2;
	}

	if (strcmp(argv[1], "-en") == 0) {
		encrypt(argv[2], argv[3], argv[4], argv[5], lib);
	} else if (strcmp(argv[1], "-de") == 0) {
		decrypt(argv[2], argv[3], argv[4], argv[5], lib);
	} else {
		printHelp();
		return 1;
	}

	dlclose(lib);
	return 0;
}

