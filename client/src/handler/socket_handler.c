#include "socket_handler.h"

int open_connection(int port, char *address) {
    int client_fd = init_socket();
    error_exit(client_fd, "Error to open socket");
    int status = connect_socket(client_fd, address, port);
    error_exit(status, "Error to connect to address");
    return client_fd;
}

void send_net(unsigned len, void *buf, int client_fd) {
    int status = send_to_socket(client_fd, len, buf);
    error_exit(status, "Error to send data to socket");
}
