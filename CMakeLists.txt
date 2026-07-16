cmake_minimum_required(VERSION 3.10)
project(mini_edr CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(mini-edr src/main.cpp)

# pthread needed on some distros for std::thread
find_package(Threads REQUIRED)
target_link_libraries(mini-edr Threads::Threads)
