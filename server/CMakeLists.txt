cmake_minimum_required(VERSION 3.10)
project(llp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}   -Wall -Wextra -pedantic -Wmissing-prototypes -Wstrict-prototypes -fsanitize-address-use-after-scope -Wno-unused-command-line-argument -g")

# Find protobuf-c and make it required (on Ubuntu it is libprotobuf-c)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

# List all protobuf object names
set(PROTO_OBJECTS
    entity
    filter
    iterator
    node
    noderesponce
    operation
    property
    propertyresponce
    relationship
    relationshipnoderesponce
    request
    responce
    simplenode
    typeelement
    valuetype
)

set(BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/binary)

# Generate .c and .h files for each object in the proto directory
foreach(object ${PROTO_OBJECTS})
    list(APPEND PROTO_GENERATED_SRC
        ${BINARY_DIR}/${object}.pb-c.c
        ${BINARY_DIR}/${object}.pb-c.h
    )
    add_custom_command(
        OUTPUT ${BINARY_DIR}/${object}.pb-c.c ${BINARY_DIR}/${object}.pb-c.h
        COMMAND protoc-c --c_out=${BINARY_DIR} --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/src/proto ${CMAKE_CURRENT_SOURCE_DIR}/src/proto/${object}.proto
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/proto/${object}.proto
    )
endforeach()

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/**.c EXCLUDE binary/*)
file(GLOB_RECURSE HEADERS ${CMAKE_CURRENT_LIST_DIR}/include/**.h EXCLUDE binary/*)

include_directories(include)

add_library(proto_server ${PROTO_GENERATED_SRC})
target_include_directories(proto_server PUBLIC ${BINARY_DIR})

add_executable(${PROJECT_NAME} ${PROTO_GENERATED_SRC})

target_sources(${PROJECT_NAME} PRIVATE ${SOURCES} PUBLIC ${HEADERS} ${PROTOBUF_C_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} ${PROTOBUF_C_LIBRARIES})

add_library(${PROJECT_NAME}_lib ${SOURCES})

# add_executable(server ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c ${PROTO_GENERATED_SRC})
# target_include_directories(server PUBLIC
#                                "${PROJECT_BINARY_DIR}"
#                                ${PROTOBUF_C_INCLUDE_DIRS}
#                                PRIVATE ${SOURCES} PUBLIC ${HEADERS}
# )