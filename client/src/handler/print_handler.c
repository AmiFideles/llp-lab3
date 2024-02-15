#include "print_handler.h"
#include <stdint.h>

void print_simple_responce(ResponceMessage *res) {
    printf("Responce - Status: %d, Message: %s\n", res->status, res->message);
}

void print_white_space(int depth) {
    for (int i = 0; i < depth; ++i) {
        printf("   ");
    }
}

void print_simple_node_message(SimpleNodeMessage *snm, int depth) {
    print_white_space(depth);
    printf("type: %s,\n", snm->type);
    print_white_space(depth);
    printf("id: %d,\n", snm->id);
    print_white_space(depth);
    printf("name: %s\n", snm->name);
}

void print_property_responce(PropertyResponce *pr, int depth) {
    print_white_space(depth);
    printf("{\n");
    print_white_space(depth + 1);
    printf("value_type: %d,\n", pr->value_type);
    print_white_space(depth + 1);
    printf("type: %s,\n", pr->type);
    print_white_space(depth + 1);
    printf("value: %s\n", pr->value);
    print_white_space(depth);
    printf("}\n");
}

void print_relationship_node_responce(RelationshipNodeResponce *rnr, int depth) {
    print_white_space(depth);
    printf("{\n");
    print_white_space(depth + 1);
    printf("relation_type: %s,\n", rnr->relation_type);
    print_simple_node_message(rnr->node, depth + 1);
    if (rnr->property != NULL) print_property_responce(rnr->property, depth + 1);
    print_white_space(depth);
    printf("}\n");
}

void print_node_responce(NodeResponce *nr, int depth) {
    print_white_space(depth);
    printf("node: {\n");
    print_simple_node_message(nr->simple_node, depth + 1);
    print_white_space(depth + 1);
    printf("relationships: [\n");
    if (nr->n_relationships > 0) {
        for (uint32_t i = 0; i < nr->n_relationships - 1; i++) {
            print_relationship_node_responce(nr->relationships[i], depth + 2);
            print_white_space(depth + 2);
            printf(",\n");
        }
        
        print_relationship_node_responce(nr->relationships[nr->n_relationships - 1], depth + 2);
    }
    print_white_space(depth + 1);
    printf("],\n");
    
    print_white_space(depth + 1);
    printf("properties: [\n");
    if (nr->n_properties > 0) {
        for (uint32_t i = 0; i < nr->n_properties - 1; i++) {
            print_property_responce(nr->properties[i], depth + 2);
            print_white_space(depth + 2);
            printf(",\n");
        }
        print_property_responce(nr->properties[nr->n_properties - 1], depth + 2);
    }
    print_white_space(depth + 1);
    printf("]\n");
    print_white_space(depth);
    printf("}\n");
}

void print_simple_responce_message(ResponceMessage *rm) {
    printf("Responce: {\n");
    print_white_space(1);
    printf("status: %d,\n", rm->status);
    print_white_space(1);
    printf("message: %s,\n", rm->message);
    print_node_responce(rm->node, 1);
    printf("}\n");
}
