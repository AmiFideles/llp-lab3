#include "responce.pb-c.h"
#include <stdio.h>

void print_simple_responce(ResponceMessage *res);
void print_white_space(int depth);
void print_simple_node_message(SimpleNodeMessage *snm, int depth);
void print_relationship_node_responce(RelationshipNodeResponce *rnr, int depth);
void print_property_responce(PropertyResponce *pr, int depth);
void print_node_responce(NodeResponce *nr, int depth);
void print_simple_responce_message(ResponceMessage *rm);
