cmake_minimum_required(VERSION 3.20)
project(EpsHookV2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(epshook STATIC epshook.cpp)
target_include_directories(epshook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if(MSVC)
    target_compile_options(epshook PRIVATE /W4)
endif()

option(EPSHOOK_BUILD_BENCH "Build benchmark (fetches MinHook)" ON)
if(EPSHOOK_BUILD_BENCH)
    include(FetchContent)
    FetchContent_Declare(minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG master
    )
    FetchContent_MakeAvailable(minhook)
    add_executable(bench bench/bench.cpp)
    target_link_libraries(bench PRIVATE epshook minhook)
endif()
