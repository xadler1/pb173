#ifndef ASSIGNMENT_HPP
#define ASSIGNMENT_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <dlfcn.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include "types.hpp"

#define LIB_PATH "./libs/libmbedcrypto.so"

/**
 * checks path for read permission
 * @param file	path to file to test
 * @return true if reading is possible
 */
bool checkRead(const std::string &file)
{
	if (FILE *f = fopen(file.c_str(), "r")) {
		fclose(f);
		return true;
	}
	std::cerr << "Input file can not be read" << std::endl;
	return false;
}

/**
 * checks path for write permission
 * @param file	path to file to test
 * @return true if writing is possible, false oterwise
 */
bool checkWrite(const std::string &file)
{
	if (FILE *f = fopen(file.c_str(), "w")) {
		fclose(f);
		return true;
	}
	std::cerr << "Output file can not be written to" << std::endl;
	return false;
}

/**
 * checks if path in is readable AND path out is writable
 * @param in	path to file to test readability
 * @param out	path to file to test writeability
 * @return true if in is readable AND out is wirtabale, false oterwise
 */
bool checkPaths(const std::string &in, const std::string &out)
{
	return checkRead(in) && checkWrite(out);
}

/**
 * hashes the input with sha512
 * @param in	input characters
 * @param len	length of input
 * @param out	stream for writing the hash
 * @param lib	dynamic library to load hash function
 * @return 0 success, 2 library does not have required symbol
 */
int hash(unsigned char *in, size_t len, std::ostream &out, void *lib)
{
	typedef int (*sha512_t)(const unsigned char *, size_t, unsigned char[], int);
	sha512_t sha512 = reinterpret_cast<sha512_t>(dlsym(lib, "mbedtls_sha512_ret"));
	if (!sha512) {
		std::cerr << dlerror() << std::endl;
		return 2;
	}

	unsigned char hash[64];

	sha512(in, len, hash, 0);

	out << std::hex;

	for (size_t i = 0; i < 64; ++i) {
		out << std::setfill('0') << std::setw(2) << static_cast<unsigned>(hash[i]);
	}

	out << std::dec << std::endl;

	return 0;
}

/**
 * checks that given argument is exactly 16 characters long
 * @param arg	char* to be checked
 * @return true if argument is 16 characters long, false oterwise
 */
bool checkKeyVec(char *arg)
{
	for (size_t i = 0; i < 16; ++i) {
		if (arg[i] == '\0') {
			return false;
		}
	}

	return (arg[16] == '\0');
}

/**
 * encrypts file using aes-128 in cbc mode using PKCS#7 padding and writes hash of encrypted file
 * @param keyarg	key used for encryption, 16 characters long
 * @param vecarg	initialization vector, 16 characters long
 * @param inputPath	path of input file
 * @param outputPath	path of output file
 * @param lib		dynamic library to load aes encryption function
 * @return 0 success, 2 library does not have required symbol
 */
int encrypt(char *keyarg, char *vecarg, const std::string &inputPath, const std::string &outputPath, void *lib)
{
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

	// reading input
	std::fstream fin(inputPath, std::ios::in);
	std::fstream fout(outputPath, std::ios::out);

	while (!fin.eof()) {
		++input_len;
		input.push_back(fin.get());
	}

	// remove eof character
	--input_len;
	input.pop_back();

	// add padding
	size_t pad = input_len % 16;

	for (size_t i = pad; i < 16; ++i) {
		++input_len;
		input.push_back(16 - pad);

	}

	std::vector<unsigned char> output(input_len);

	aes_setkey_enc(&aes, key, 128);
	aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input_len, iv, &input[0], &output[0]);

	fout.write(reinterpret_cast<char *> (&output[0]), input_len);

	// hashing
	std::fstream fouthash(outputPath + ".digest", std::ios::out);

	hash(&output[0], input_len, fouthash, lib);


	return 0;
}

/**
 * decrypts file using aes-128 in cbc mode using PKCS#7 padding and compares hash with hash from inputPath.digest
 * @param keyarg	key used for encryption, 16 characters long
 * @param vecarg	initialization vector, 16 characters long
 * @param inputPath	path of input file
 * @param outputPath	path of output file
 * @param lib		dynamic library to load aes encryption function
 * @return 0 success, 2 library does not have required symbol
 */
int decrypt(char *keyarg, char *vecarg, const std::string &inputPath, const std::string &outputPath, void *lib)
{
	std::vector<unsigned char> input;
	size_t input_len = 0;

	std::fstream fin(inputPath, std::ios::in);
	std::fstream fout(outputPath, std::ios::out);

	while (!fin.eof()) {
		++input_len;
		input.push_back(fin.get());
	}

	// remove eof character
	--input_len;
	input.pop_back();

	/* hash comparison */
	std::stringstream computed;
	std::stringstream supplied;

	hash(&input[0], input_len, computed, lib);

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



	std::vector<unsigned char> output(input_len);

	//std::cout << "input_len = " << input_len << std::endl;

	aes_setkey_dec(&aes, key, 128);
	aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, iv, &input[0], &output[0]);

	// remove padding
	size_t pad = output[input_len - 1];

	for (size_t i = 0; i < input_len - pad; ++i) {
		fout << output[i];
	}

	return 0;
}

#endif // ASSIGNMENT_HPP
