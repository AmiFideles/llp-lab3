#pragma once

#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080
#define MAX_BUFFER_SIZE 4096

int init_socket(void);

int connect_socket(int client_fd, const char *server_addr, int port);

int send_to_socket(int client_fd, size_t len, const void *buf);

ssize_t receive_from_socket(int client_fd, uint8_t *buf);

void close_socket(int client_fd);

int bind_socket(int socket_fd);

int listen_socket(int socket_fd);

int accept_socket(int socket_fd);
