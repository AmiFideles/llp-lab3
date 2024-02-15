#include "client_handler.h"
#include "../parser/ast.h"
#include "../parser/parser_ast.h"
#include "print_handler.h"
#include "socket_handler.h"
#include "request.pb-c.h"
#include "responce.pb-c.h"
#include <stdlib.h>

void handle_client_input(int type, int client_fd, const char *file_path) {
    if (type) {
        handle_input(client_fd);
    } else {
        handle_file(client_fd, file_path);
    }
}

typedef struct yy_buffer_state *YY_BUFFER_STATE;

extern YY_BUFFER_STATE yy_scan_string(char *str);

extern void yy_delete_buffer(YY_BUFFER_STATE buffer);

void handle_input(int client_fd) {
    int c;
    int query = 0;
    struct DynamicBuffer buffer1 = {0};
    while ((c = getchar()) != 0) {
        if (query) {
            DynamicBufferPut(&buffer1, (char) c);
            if (c == ';') {
                query = 0;
                DynamicBufferPut(&buffer1, '\0');
                DynamicBufferReset(&buffer1);
//                printf("%s", buffer1.data);
                YY_BUFFER_STATE buffer = yy_scan_string(buffer1.data);
                if (yyparse()) {
                    printf("Parsing failed\n");
                } else {
                    int parse_result = yyparse();
                    parse_send_request(client_fd);
                    root.left = NULL;
                    root.right = NULL;
                    yy_delete_buffer(buffer);
                }
            }
        } else {
            if (c != ';' && c != '\n') {
                query = 1;
                DynamicBufferPut(&buffer1, (char) c);
            }
            if (c == '\\') {
                c = getchar();
                switch (c) {
                    case 'q': {
                        goto out;
                    }
                    default: {
                        printf("Try \\? for help. \n");
                    }
                }
            }
        }
    }
    out:
    DynamicBufferFree(&buffer1);
}

void handle_file(int client_fd, const char *file_path) {
    yyin = fopen(file_path, "r");
    if (!yyin) {
        printf("Can't open file %s\n", file_path);
        error_exit(-1, "");
    }

    while (!yyparse()) {
        parse_send_request(client_fd);
        root.left = NULL;
        root.right = NULL;
    }

    fclose(yyin);
}

static void copy_request(RequestMessage *dest, RequestMessage *source) {
    dest->operation = source->operation;
    dest->type = source->type;
    dest->filter = source->filter;

    dest->entity = source->entity;
    dest->node = source->node;
    dest->relationship = source->relationship;
    dest->property = source->property;

    dest->relationships = source->relationships;
    dest->n_relationships = source->n_relationships;
    dest->properties = source->properties;
    dest->n_properties = source->n_properties;
}

void handle_responce_with_iterator(RequestMessage *request, ResponceMessage *responce, int client_fd) {
    void *buf;
    unsigned len;
    RequestMessage *new_request = malloc(sizeof(RequestMessage));
    uint8_t *buffer;
    ssize_t length;

    request_message__init(new_request);
    copy_request(new_request, request);

    while (responce->status != 404) {
        print_simple_responce_message(responce);
        new_request->iterator = responce->iterator;

        len = request_message__get_packed_size(new_request);
        buf = malloc(len);

        request_message__pack(new_request, buf);
        send_net(len, buf, client_fd);

        buffer = (uint8_t *) malloc(sizeof(uint8_t) * 4096);
        length = receive_from_socket(client_fd, buffer);

        responce_message__free_unpacked(responce, NULL);
        responce = responce_message__unpack(NULL, length, buffer);

        free(buffer);
        free(buf);
    }
    // print_simple_responce(responce);
    responce_message__free_unpacked(responce, NULL);
    request_message__free_unpacked(request, NULL);
}

void parse_send_request(int client_fd) {
    RequestMessage *request;
    void *buf;
    unsigned len;

    ResponceMessage *responce;
    uint8_t *buffer;
    ssize_t length;

    request = parse_ast(&root);
    len = request_message__get_packed_size(request);
    buf = malloc(len);

    request_message__pack(request, buf);
    send_net(len, buf, client_fd);

    buffer = (uint8_t *) malloc(sizeof(uint8_t) * 4096);
    length = receive_from_socket(client_fd, buffer);
    responce = responce_message__unpack(NULL, length, buffer);

    if (responce == NULL) {
        printf("Error occured while recieving message from server\n");
        request_message__free_unpacked(request, NULL);
    } else if (responce->status == 201) {
        handle_responce_with_iterator(request, responce, client_fd);
    } else {
        print_simple_responce(responce);
        responce_message__free_unpacked(responce, NULL);
        request_message__free_unpacked(request, NULL);
    }

    free(buf);
    free(buffer);
}

int DynamicBufferPut(struct DynamicBuffer *buffer, char c) {
    if (buffer->data == NULL) {
        buffer->data = malloc(4);
        buffer->size = 4;
    }
    if (buffer->size == buffer->ptr) {
        size_t newSize = buffer->size * 2;
        char *newData = malloc(newSize);
        memcpy(newData, buffer->data, buffer->size);
        free(buffer->data);
        buffer->data = newData;
        buffer->size = newSize;
    }
    buffer->data[buffer->ptr++] = c;
    return 0;
}

void DynamicBufferFree(struct DynamicBuffer *buffer) {
    free(buffer->data);
    *buffer = (struct DynamicBuffer) {0};
}

void DynamicBufferReset(struct DynamicBuffer *buffer) {
    buffer->ptr = 0;
}