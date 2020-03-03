#include <sstream>
#include <dlfcn.h>
#include <string>
#include <cstring>
#include <iostream>
#include <ostream>
#include "catch.hpp"
#include "assignment.hpp"

TEST_CASE("only test case")
{
	void *lib = dlopen(LIB_PATH, RTLD_LAZY);
	REQUIRE(lib);


	SECTION("hash")
	{
		std::stringstream out;
		std::stringstream out2;
		std::vector<unsigned char> str = {'a', 'a', 'a', 'a', 'b', 'b'};
		std::vector<unsigned char> str2 = {'a', 'a', 'a', 'a', 'b', 'b', '\n'};
		hash(&str[0], 6, out, lib);
		std::string s = out.str();
		s.pop_back();
		REQUIRE("92ed8904383aacd28b2a1a9cbd10c022acc5a620d648f11474a5c825a46a2edfaa6fb774b04b73dfc49f5e3aa285b39747217d84289dcbc95c751d56374daf1c" == s);

		hash(&str2[0], 7, out2, lib);
		s = out2.str();
		s.pop_back();
		REQUIRE("663bb8c479d88573c1de4467d1fef6a0773fd653153e33311c2448c28def86fb18bf31ebfdf5797a1d8c677a949b67111a260e1fd4eeb3e0f1c5e654763e65a2" == s);
	}



	SECTION("input/output files")
	{
		REQUIRE(checkRead("/etc/fstab"));
		REQUIRE(!checkRead("/etc/shadow"));
		REQUIRE(checkWrite("/tmp/test"));
		REQUIRE(!checkWrite("/etc/fstab"));
	}

	dlclose(lib);



}
