cmake_minimum_required(VERSION 3.10)
project(llp3 VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic -Wmissing-prototypes -Wstrict-prototypes -fsanitize-address-use-after-scope -Wno-unused-command-line-argument -g")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/output)

# Add the client and server projects as subdirectories
add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(common)
