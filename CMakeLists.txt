cmake_minimum_required(VERSION 3.10)
project(ArionAgent)

# CMAKE_BUILD_TYPE can be Debug or Release
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 17)

add_definitions(-w)

add_subdirectory(src)
#add_subdirectory(test)
