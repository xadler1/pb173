#include <iostream>
#include <dlfcn.h>
#include "types.hpp"

int main(int argc, char** argv)
{
	std::cout << "Hello, World!" << std::endl;

	// test wether library is present
	//void *lib = dlopen("./libmbedtls.so", RTLD_LAZY);
	void *math = dlopen("/lib/libm.so.6", RTLD_LAZY);

	mbedtls_sha512_context ctx;
	auto *pctx = &ctx;

	//void (*sha512_init)(mbedtls_sha512_context*) = dlsym(lib, "mbedtls_sha512_init");
	//
	typedef double (*kosinus_t)(double);
	kosinus_t kos = (kosinus_t) dlsym(math, "cos");

	std::cout << kos(0.0) << std::endl;
	std::cout << "NECO" << std::endl;



	//dlclose(math);
	//std::cout << "NECO" << std::endl;
	//dlclose(lib);
	std::cout << "NECO" << std::endl;
	return 0;
}
