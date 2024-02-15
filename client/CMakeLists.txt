cmake_minimum_required(VERSION 3.10)

# Set project name and version
project(MyProgram VERSION 1.0)

# Add C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find protobuf-c and make it required (on Ubuntu it is libprotobuf-c)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

# Find flex and bison
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

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

set(BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/binary)

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

# Flex and Bison file generation
FLEX_TARGET(GraphQLScanner ${CMAKE_CURRENT_SOURCE_DIR}/src/parser/graphql.l ${BINARY_DIR}/graphql_lexer.c)
BISON_TARGET(GraphQLParser ${CMAKE_CURRENT_SOURCE_DIR}/src/parser/graphql.y ${BINARY_DIR}/graphql_parser.c)
ADD_FLEX_BISON_DEPENDENCY(GraphQLScanner GraphQLParser)

# Collect all .h and .c files from the directories in your project root (recursively)
file(GLOB_RECURSE PARSER_HEADERS "*.h" EXCLUDE binary/*)
file(GLOB_RECURSE PARSER_SOURCES "*.c" EXCLUDE binary/*)

# Remove the Flex and Bison generated files from the collected sources to avoid duplicates
# list(REMOVE_ITEM PARSER_SOURCES ${BISON_GraphQLParser_OUTPUTS} ${FLEX_GraphQLScanner_OUTPUTS})

# Add the Flex and Bison outputs to the sources list
list(APPEND PARSER_SOURCES ${BISON_GraphQLParser_OUTPUTS} ${FLEX_GraphQLScanner_OUTPUTS})

# Create the parser library
add_library(parser ${PARSER_SOURCES} ${PARSER_HEADERS})
target_include_directories(parser PUBLIC ${BINARY_DIR})

add_library(proto ${PROTO_GENERATED_SRC})
target_include_directories(proto PUBLIC ${BINARY_DIR})

# Create the parser library
# add_library(parser ${BISON_GraphQLParser_OUTPUTS} ${FLEX_GraphQLScanner_OUTPUTS} parser/ast.c parser/ast.h)
# target_include_directories(parser PUBLIC ${BINARY_DIR})

# Function to build each program (serialize and deserialize)
function(build_program program_name main_src)
    add_executable(${program_name} ${CMAKE_CURRENT_SOURCE_DIR}/src/${main_src} ${PROTO_GENERATED_SRC})
    target_include_directories(${program_name} PUBLIC
                               "${PROJECT_BINARY_DIR}"
                               ${PROTOBUF_C_INCLUDE_DIRS}
    )
    target_link_libraries(${program_name} ${PROTOBUF_C_LIBRARIES} parser)
endfunction()

# Build the serialize and deserialize programs
build_program(main main.c)

