#include "../net/socket.h"
#include "../utils/io_utils.h"

int open_connection(int port, char *address);
void send_net(unsigned len, void *buf, int client_fd);
