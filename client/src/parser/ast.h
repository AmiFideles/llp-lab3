// ast.h
#ifndef AST_H
#define AST_H

#include <stdbool.h>

typedef enum {
    QUERY,
    MUTATION,
    BOOLEAN,
    NULL_VALUE,
    FIELD,
    VARIABLE,
    NUMBER,
    STRING,
    PARENTHESIS,
    COLON,
    EQUAL,
    BRAKET_OPEN,
    BRAKET_CLOSE,
    CURLY_BRACE_OPEN,
    CURLY_BRACE_CLOSE,
    COMMA,
    DOT,
    EQUAL_OPERATOR,
    LOWER_OPERATOR,
    GREATER_OPERATOR,
    GREATER_EQUAL,
    LOWER_EQUAL,
    NOT_EQUAL,
    NOT,
    OR,
    AND,
    INTEGER,
    DOUBLE,
    IDENTIFIER,
    PLUS_OPERATION,
    MINUS_OPERATION,
    MULTIPLY_OPERATION,
    DIVIDE_OPERATION,
    RET,
    DOUBLE_DOT,
    QOUTE,
    ARGUMENT,
    FILTER,
    SELECTION,
    OPERATION,
    VALUE,
    MATH_VALUE,
    VAR_VALUE,
    NAME_DEFINITION,
    VARIABLE_DEFINITION,
    SELECTION_SET,
    TYPE,
    JSON,
    JSON_OBJECT,
    JSON_ELEMENT,
    JSON_ARRAY,
    VALUES,
    JSON_ELEMENTS,
    ROOT,
    AST_NODE_TYPE_COUNT
} AstNodeType;

extern const char *astNodeTypeToString[];

typedef struct Node {
  AstNodeType type;
  union {
        double double_val;
        int int_val;
        char* str_val;
        int bool_val;
  } value;
  struct Node *left;
  struct Node *right;
} Node;

extern Node root; 

Node *createNode_V(AstNodeType type, Node *left, Node *right);
Node *createNode_I(AstNodeType type, int val, Node *left, Node *right);
Node *createNode_D(AstNodeType type, double val, Node *left, Node *right);
Node *createNode_B(AstNodeType type, bool val, Node *left, Node *right);
Node *createNode_S(AstNodeType type, char *val, Node *left, Node *right);

void printRoot(void);
void addJsonInput(Node *node);
void addRequest(Node *node);
const char *getAstNodeTypeName(AstNodeType type);
void printTree(Node *node, int depth, int is_left, int *parent_dir);
char* copyStr(const char* src);
#endif
