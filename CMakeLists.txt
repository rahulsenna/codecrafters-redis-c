cmake_minimum_required(VERSION 3.13)

project(codecrafters-redis)
set(CMAKE_BUILD_TYPE Debug)
file(GLOB_RECURSE SOURCE_FILES src/*.c src/*.h)

set(CMAKE_C_STANDARD 23) # Enable the C23 standard

add_executable(redis ${SOURCE_FILES})
target_compile_options(redis PRIVATE
  -g3
  -fno-omit-frame-pointer
)
target_link_options(redis PRIVATE -rdynamic)
target_link_libraries(redis m)