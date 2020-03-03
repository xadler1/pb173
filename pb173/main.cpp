#include <iostream>
#include <dlfcn.h>
#include <cstring>
#include "assignment.hpp"


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
	std::cout << std::endl;
	std::cout << "return codes:" << std::endl;
	std::cout << "0\tno problems" << std::endl;
	std::cout << "1\tsyntax error" << std::endl;
	std::cout << "2\tdynamic library error" << std::endl;
	std::cout << "3\tinput/output file error" << std::endl;
	std::cout << "4\tencrypted message has different hash" << std::endl;
}

int main(int argc, char** argv)
{
	if (argc != 6) {
		printHelp();
		return 1;
	}

	if (!checkPaths(argv[4], argv[5])) {
		return 3;
	}

	void *lib = dlopen(LIB_PATH, RTLD_LAZY);

	if (!lib) {
		std::cerr << dlerror();
		std::cerr << "HERE IT WAS" << std::endl;
		return 2;
	}

	int exit = 0;

	if (strcmp(argv[1], "-en") == 0) {
		exit = encrypt_hash(argv[2], argv[3], argv[4], argv[5], lib);
	} else if (strcmp(argv[1], "-de") == 0) {
		exit = decrypt_compare(argv[2], argv[3], argv[4], argv[5], lib);
	} else {
		printHelp();
		return 1;
	}

	dlclose(lib);
	return exit;
}
