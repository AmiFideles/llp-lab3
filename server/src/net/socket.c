#include "../include/net/socket.h"
#include <stdlib.h>

int init_socket(void) {
    int socket_fd;
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    return socket_fd;
}

int connect_socket(int socket_fd, const char *server_addr, int port) {
    (void) server_addr;
    (void) port;


    int status;
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    if ((status = connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    return 0;
}

int send_to_socket(int socket_fd, size_t len, const void *buf) {
    if (send(socket_fd, buf, len, 0) == -1) {
        printf("Error sending data to socket\n");
        return -1;
    }
    return 0;
}

int receive_from_socket(int socket_fd, uint8_t *buf) {
    ssize_t len = recv(socket_fd, buf, MAX_BUFFER_SIZE - 1, 0);
    if (len == -1) {
        printf("Error to receive data from socket\n");
        return -1;
    }
    buf[len] = '\0';
    return len;
}

void close_socket(int socket_fd) {
    close(socket_fd);
}

int bind_socket(int socket_fd, int port) {
    struct sockaddr_in address;
    int opt = 1;
    
    if (setsockopt(socket_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
 
    if (bind(socket_fd, (struct sockaddr*)&address,sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int listen_socket(int socket_fd) {
    if (listen(socket_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int accept_socket(int socket_fd) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    return accept(socket_fd, (struct sockaddr*) &address, &addrlen);
}
