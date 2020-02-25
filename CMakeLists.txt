cmake_minimum_required(VERSION 3.0)
project(aes_and_sha512)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wextra -pedantic -Wold-style-cast -ldl")

add_executable(assignment assignment.cpp)
