#include "io_utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void println(const char *line, ...) {
    va_list args;
    va_start(args, line);
    vprintf(line, args);
    printf("\n");
    va_end(args);
}

void exit_with_error(const char *line, ...) {
    va_list args;
    va_start(args, line);
    vprintf(line, args);
    printf("\n");
    va_end(args);
    exit(EXIT_FAILURE);
}

void error_exit(int var, const char *line, ...) {
    if (var == -1) {
        va_list args;
        va_start(args, line);
        vprintf(line, args);
        printf("\n");
        va_end(args);
        exit(EXIT_FAILURE);
    }
}

void debug(int num, const char *line, ...) {
    println("Debug %i", num);
    va_list args;
    va_start(args, line);
    vprintf(line, args);
    printf("\n");
    va_end(args);
}

void print_test_format(const char *line, ...) {
    println("---------------------------");
    va_list args;
    va_start(args, line);
    vprintf(line, args);
    printf("\n");
    va_end(args);
    println("---------------------------");
}

void write_to_file(unsigned len, void *buf, char *filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error: unable to open file for writing.\n");
        return;
    }

    size_t bytes_written = fwrite (buf, len, 1, file);
    if (bytes_written != 1) {
        perror("Error: unable to write the data to the file.\n");
        fclose(file);
        return;
    }

    fclose(file);
}
