#include <stdio.h>
#include "../utils/io_utils.h"
#include "request.pb-c.h"
#include "responce.pb-c.h"

#define YY_STDINIT
#define YYSTYPE double
extern YYSTYPE yylval;

extern int yyparse(void);

extern FILE *yyin;


void handle_client_input(int type, int client_fd, const char *file_path);
void handle_input(int client_fd);
void handle_file(int client_fd, const char *file_path);
void parse_send_request(int client_fd);
void handle_responce_with_iterator(RequestMessage *request, ResponceMessage *responce, int client_fd);
struct DynamicBuffer {
    char *data;
    size_t ptr;
    size_t size;
};

int DynamicBufferPut(struct DynamicBuffer *buffer, char c);

void DynamicBufferFree(struct DynamicBuffer *buffer);

void DynamicBufferReset(struct DynamicBuffer *buffer);