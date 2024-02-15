#pragma once

#include "../data/cursor.h"

#define MAX_MSG_SIZE 4096

int start_server(int port);
void accept_requests(int server_fd, Cursor *cursor);
void close_connection(int server_fd);
