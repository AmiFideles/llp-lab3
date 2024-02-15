#include <stdio.h>
#include <stdlib.h>
#include "./parser/ast.h"
#include "./parser/parser_ast.h"
#include "../binary/request.pb-c.h"
#include "./net/socket.h"
#include "responce.pb-c.h"
#include "typeelement.pb-c.h"
#include "utils/io_utils.h"
#include "./handler/socket_handler.h"
#include "./handler/client_handler.h"

int main(int argc, char **argv) {
    --argc;
    ++argv;
    if (argc < 3) {
        printf("Usage: ./client <server address> <port> <type [0|1]> [filename]\n");
        return 1;
    }
    char *server_address = argv[0];
    int port = atoi(argv[1]);
    int type = atoi(argv[2]);
    char *file_path;
    if (argc != 4) {
        file_path = "";
    } else {
        file_path = argv[3];
    }

    // char *server_address = "127.0.0.1";
    // int port = 8080;
    // int type = 0;
    // char *file_path = "../test_input/select";
    // char *file_path = "../test_input/create_rel";
    // char *file_path = "../test_input/create_nodes";
    // char *file_path = "../test_input/create_entity";

    printf("Server address: %s\n", server_address);
    printf("Port: %d\n", port);

    int client_fd = open_connection(port, server_address);
    handle_client_input(type, client_fd, file_path);
    close_socket(client_fd);

    return 0;
}
