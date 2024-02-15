#pragma once

void println(const char *line, ...);

void error_exit(int var, const char *line, ...);

void debug(int num, const char *line, ...);

void print_test_format(const char *line, ...);

void exit_with_error(const char *line, ...);

void write_to_file(unsigned len, void *buf, char *filename);
