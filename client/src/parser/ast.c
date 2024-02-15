#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "ast.h"

const char *astNodeTypeToString[] = {
    "QUERY",
    "MUTATION",
    "BOOLEAN",
    "NULL_VALUE",
    "FIELD",
    "VARIABLE",
    "NUMBER",
    "STRING",
    "PARENTHESIS",
    "COLON",
    "EQUAL",
    "BRAKET_OPEN",
    "BRAKET_CLOSE",
    "CURLY_BRACE_OPEN",
    "CURLY_BRACE_CLOSE",
    "COMMA",
    "DOT",
    "EQUAL_OPERATOR",
    "LOWER_OPERATOR",
    "GREATER_OPERATOR",
    "GREATER_EQUAL",
    "LOWER_EQUAL",
    "NOT_EQUAL",
    "NOT",
    "OR",
    "AND",
    "INTEGER",
    "DOUBLE",
    "IDENTIFIER",
    "PLUS_OPERATION",
    "MINUS_OPERATION",
    "MULTIPLY_OPERATION",
    "DIVIDE_OPERATION",
    "RET",
    "DOUBLE_DOT",
    "QOUTE",
    "ARGUMENT",
    "FILTER",
    "SELECTION",
    "OPERATION",
    "VALUE",
    "MATH_VALUE",
    "VAR_VALUE",
    "NAME_DEFINITION",
    "VARIABLE_DEFINITION",
    "SELECTION_SET",
    "TYPE",
    "JSON",
    "JSON_OBJECT",
    "JSON_ELEMENT",
    "JSON_ARRAY",
    "VALUES",
    "JSON_ELEMENTS",
    "ROOT"
};

Node root = {ROOT, 0, NULL, NULL};

void printRoot(void) {
    int *parent_dir = (int *) malloc(sizeof(int) * 256);
    printTree(&(root), 0, true, parent_dir);
}

void addJsonInput(Node *node) {
    if (root.right != NULL) printf("ERROR to assign json node to non null root.right");
    if (root.right == NULL) root.right = node;
}

void addRequest(Node *node) {
    if (root.left != NULL) printf("ERROR to assign request node to non null root.left");
    if (root.left == NULL) root.left = node;
}

Node *createNode_V(AstNodeType type, Node *left, Node *right) {
  Node *newNode = (Node *) malloc(sizeof(Node));
  newNode->type = type;
  newNode->left = left;
  newNode->right = right;
  return newNode;
}

Node *createNode_I(AstNodeType type, int val, Node *left, Node *right) {
  Node *newNode = (Node *) malloc(sizeof(Node));
  newNode->type = type;
  newNode->value.int_val = val;
  newNode->left = left;
  newNode->right = right;
  return newNode;
}

Node *createNode_D(AstNodeType type, double val, Node *left, Node *right) {
  Node *newNode = (Node *) malloc(sizeof(Node));
  newNode->type = type;
  newNode->value.double_val = val;
  newNode->left = left;
  newNode->right = right;
  return newNode;
}

Node *createNode_B(AstNodeType type, bool val, Node *left, Node *right) {
  Node *newNode = (Node *) malloc(sizeof(Node));
  newNode->type = type;
  newNode->value.bool_val = val;
  newNode->left = left;
  newNode->right = right;
  return newNode;
}

char* copyStr(const char* src) {
    char* dest = malloc(strlen(src));
    strcpy(dest, src);
    return dest;
}

Node *createNode_S(AstNodeType type, char *val, Node *left, Node *right) {
  Node *newNode = (Node *) malloc(sizeof(Node));
  newNode->type = type;
  newNode->value.str_val = copyStr(val);;
  newNode->left = left;
  newNode->right = right;
  return newNode;
}

const char *getAstNodeTypeName(AstNodeType type) {
    if (type < AST_NODE_TYPE_COUNT) {
        return astNodeTypeToString[type];
    } else {
        return "UNKNOWN";
    }
}


void printTree(Node *node, int depth, int is_left, int *parent_dir) {
    if (node == NULL) {
        return;
    }
    
    for (int i = 0; i < depth; ++i) {
        if (!parent_dir[i]) {
            printf("   ");
        } else {
            printf("│  ");
        }
    }

    if (depth != 0) {
        if (is_left) {
            printf("├");
        } else {
            printf("└");
        }
    }

    printf("%s ", getAstNodeTypeName(node->type));
    switch (node->type) {
        case DOUBLE:
            printf(": %f", node->value.double_val);
            break;
        case INTEGER:
            printf(": %d", node->value.int_val);
            break;
        case STRING:
            printf(": \"%s\"", node->value.str_val);
            break;
        case FIELD:
            printf(": \"%s\"", node->value.str_val);
            break;
        case VARIABLE:
            printf(": \"%s\"", node->value.str_val);
            break;
        case BOOLEAN:
            printf(": %s", node->value.bool_val ? "true" : "false");
        default:
            break;
    }

    printf("\n");
    if (depth != 0) parent_dir[depth] = is_left;
    if (node->right != NULL) printTree(node->left, depth + 1, 1, parent_dir);
    else {
        printTree(node->left, depth + 1, 0, parent_dir);
    }
    
    printTree(node->right, depth + 1, 0, parent_dir);
}
