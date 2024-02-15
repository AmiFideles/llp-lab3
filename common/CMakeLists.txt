project(Common)

# Add C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find protobuf-c and make it required (on Ubuntu it is libprotobuf-c)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

# List all protobuf object names
set(PROTO_OBJECTS
    element
    entity
    filter
    iterator
    operation
    request
)

set(BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)

# Generate .c and .h files for each object in the proto directory
foreach(object ${PROTO_OBJECTS})
    list(APPEND PROTO_GENERATED_SRC
        ${BINARY_DIR}/${object}.pb-c.c
        ${BINARY_DIR}/${object}.pb-c.h
    )
    add_custom_command(
        OUTPUT ${BINARY_DIR}/${object}.pb-c.c ${BINARY_DIR}/${object}.pb-c.h
        COMMAND protoc-c --c_out=${BINARY_DIR} --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto ${CMAKE_CURRENT_SOURCE_DIR}/proto/${object}.proto
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/${object}.proto
    )
endforeach()

# Collect all .h and .c files from the directories in your project root (recursively)
file(GLOB_RECURSE PARSER_HEADERS "*.h" EXCLUDE build/*)
file(GLOB_RECURSE PARSER_SOURCES "*.c" EXCLUDE build/*)

# Create a library target for the common module
# add_library(proto_lib ${PROTO_GENERATED_SRC} ${PARSER_HEADERS} ${PARSER_SOURCES})

# Specify the common module include directory
# target_include_directories(proto_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})


# set(INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/net)

# add_library(proto_lib_new ${PARSER_HEADERS} ${PARSER_SOURCES})
# Add the following line
# set_target_properties(proto_lib_new PROPERTIES LINKER_LANGUAGE C)
# target_include_directories(proto_lib_new PUBLIC ${PARSER_HEADERS} ${PARSER_SOURCES})
# cmake
# cmake_minimum_required(VERSION 3.10)

# # Set project name and version
# project(Common)

# # Find protobuf-c and make it required (on Ubuntu, it is libprotobuf-c)
# find_package(PkgConfig REQUIRED)
# pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

# # List all protobuf object names
# set(PROTO_OBJECTS
#     element
#     entity
#     filter
#     iterator
#     operation
#     request
# )

# set(BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)

# # Generate .c and .h files for each object in the proto directory
# foreach(object ${PROTO_OBJECTS})
#     list(APPEND PROTO_GENERATED_SRC
#         ${BINARY_DIR}/${object}.pb-c.c
#         ${BINARY_DIR}/${object}.pb-c.h
#     )
#     add_custom_command(
#         OUTPUT ${BINARY_DIR}/${object}.pb-c.c ${BINARY_DIR}/${object}.pb-c.h
#         COMMAND protoc-c --c_out=${BINARY_DIR} --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/proto ${CMAKE_CURRENT_SOURCE_DIR}/proto/${object}.proto
#         DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/${object}.proto
#     )
# endforeach()

# # Create a library for the proto files
# add_library(proto_lib STATIC ${PROTO_GENERATED_SRC})
# target_include_directories(proto_lib PUBLIC ${BINARY_DIR})
# target_link_libraries(proto_lib ${PROTOBUF_C_LIBRARIES})
