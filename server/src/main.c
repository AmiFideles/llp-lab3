#include "../include/utils/test_utils.h"
#include "../include/utils/io_utils.h"
#include "../include/server/server_utils.h"

char log_level = 100;

int main(int argc, char *argv[]) {
    --argc;
    ++argv;

    if (argc != 2) {
        printf("Usage: ./server <port> <file_name>\n");
        return 1;
    }
    int port = atoi(argv[0]);
    char *filename = argv[1];
    
    // (void) argc;
    // (void) argv;
    // int port = 8080;
    // char *filename = "../neo4j_try";
    
    Cursor *cursor = db_open(filename);
    int server_fd = start_server(port);
    
    printf("Database created in file - %s\n", filename);
    printf("Server started on port - %d\n", port);
    
    // bool result = true;
    // result = create_test(cursor);
    //     delete_test(cursor) &&
    //     update_test(cursor);
    // if (result) {
    //     print_test_format("Tests passed");
    // } else {
    //     print_test_format("Tests failed");
    // }
    
    accept_requests(server_fd, cursor);
    // select_test(cursor);
    // delete_smoke_test(cursor);
    // update_smoke_test(cursor);
    // select_smoke_test(cursor);
    // select_delete_smoke_test(cursor);
    
    close_connection(server_fd);
    db_close(cursor);
    return 0;
}
