#include "string_utils.h"

char *int_to_string(int num) {
    int length = snprintf(NULL, 0, "%d", num) + 1;

    char *num_str = (char *)malloc(length * sizeof(char));
    sprintf(num_str, "%d", num);
    return num_str;
}

char *create_buff_string(const char *from) {
    size_t string_size = strlen(from);
    char *buff = (char *) malloc(sizeof(char) * string_size);
    strcpy(buff, from);
    return buff;
}

char *cut_quotes(const char *from) {
    char *output = (char *) malloc(sizeof(char) * (strlen(from) - 1)); // Prepare an output buffer
    int j = 0;

    for (int i = 0; i < (int) strlen(from); ++i) {
        if (from[i] != '\"') {
            output[j++] = from[i];
        }
    }
    output[j] = '\0';
    return output;
}

char *string_copy(const char *str) {
    // int len = strlen(str);
    char *new_str = (char *) malloc(sizeof(char));
    strcpy(new_str, str);
    return new_str;
}
