CXXFLAGS=-Werror -Wall -ldl
SOURCES_MAIN=pb173/main.cpp
OBJECTS_MAIN=$(SOURCES_MAIN:.cpp=.o)
SOURCES_TEST=pb173/assignment.test.cpp pb173/test-main.cpp
OBJECTS_TEST=$(SOURCES_TEST:.cpp=.o)
DEPS=pb173/assignment.hpp

all: assignment test

test: test-main
	./test-main

assignment: $(OBJECTS_MAIN)
	$(CXX) $(CXXFLAGS) -o $@ $^

test-main: $(OBJECTS_TEST)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJECTS_MAIN)
