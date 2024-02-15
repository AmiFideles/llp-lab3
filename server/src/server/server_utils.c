#include "../include/server/server_utils.h"
#include "../include/net/socket.h"
#include "../include/utils/io_utils.h"
#include "../include/server/handlers.h"
#include "../../binary/request.pb-c.h"
#include "../../binary/responce.pb-c.h"
#include <stdint.h>


int start_server(int port) {
    int server_fd = init_socket();
    int status = bind_socket(server_fd, port);
    error_exit(status, "Unable to bind port\n");
    listen_socket(server_fd);

    return server_fd;
}

void accept_requests(int server_fd, Cursor *cursor) {
    int acc_socket;
    RequestMessage *request;
    ResponceMessage *responce;
    void *buffer;
    unsigned len;
    uint8_t *buf;

    acc_socket = 0;
    while (1) {
        while (!acc_socket) {
            acc_socket = accept_socket(server_fd);
        }
        buf = (uint8_t *) malloc(MAX_MSG_SIZE);
        len = receive_from_socket(acc_socket, buf);
        request = request_message__unpack(NULL, len, buf);
        if (request == NULL) {
            fprintf(stderr,"Error unpacking incoming message\n");
            acc_socket = 0;
            continue;
        }
        responce = handle_request(request, cursor);
        len = responce_message__get_packed_size(responce);
        buffer = malloc(len);

        responce_message__pack(responce, buffer);
        send_to_socket(acc_socket, len, buffer);

        free(buf);
        free(buffer);

    }
}

void close_connection(int server_fd) {
    close_socket(server_fd);
}
