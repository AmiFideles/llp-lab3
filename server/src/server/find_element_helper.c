#include "../include/server/find_element_handler.h"
#include "../include/operations/crud_methods.h"
#include "data/constants.h"
#include "data/node.h"
#include "data/property.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

Node *find_node_from_request(Cursor *cursor, RequestMessage *request, Iterator **iter) {
    FilterMessage *filter = request->filter;
    Node *nd = (Node*) malloc(NODE_SIZE);

    if (filter->value != NULL) {
        nd->id = atoi(filter->value);
        strcpy(nd->type, filter->type_element);
        *iter = select_node_by_id(cursor, nd);
    } else {
        strcpy(nd->type, filter->type_element);
        *iter = select_all_nodes_by_type(cursor, nd);
    }
    if (request->iterator != NULL) {
        *((*iter)->offset_) = request->iterator->offset;
        *((*iter)->read_block_) = request->iterator->read_block;
    }
    if (!has_next(*iter)) {
        free_iter(*iter);
        return NULL;
    }

    free(nd);
    nd = next(*iter);
    Node *return_n = create_node_copy(nd);
    free_node(nd);
    return return_n;
}

static bool is_element_in_array(char **array, int array_length, char *element) {
    for (int i = 0; i < array_length; i++) {
        if (strcmp(array[i], element) == 0) {
            return true;
        }
    }
    return false;
}

void find_relationship_for_request(Cursor *cursor, Node *nd, int *relationships_count, Relationship ***relationships, RequestMessage *request) {
    EntityIterator *entity_iterator_rel = select_relationships_by_node(cursor, nd);

    while (entity_iterator_rel != NULL && entity_has_next(entity_iterator_rel)) {
        Relationship *rel = entity_next(entity_iterator_rel);
        if (is_element_in_array(request->relationships, request->n_relationships, rel->type)) {
            (*relationships_count)++;
            *relationships = (Relationship **) realloc(*relationships, *relationships_count * sizeof(Relationship*));
            (*relationships)[*relationships_count - 1] = create_relationship_copy(rel);
        }
        // free_relationship(rel);
    }
    free_entity_iter(entity_iterator_rel);
}

void find_nodes_by_relationships(Cursor *cursor, int relationships_count, Relationship **relationships, Node ***nodes_rel) {
    Node *node = (Node*) malloc(NODE_SIZE);
    node->name = malloc(CHAR_SIZE);
    
    for (int i = 0; i < relationships_count; i++) {
        Relationship *rel = relationships[i];
        node->id = rel->child_id;
        strcpy(node->type, rel->child_type);
        
        Iterator *iterator = select_node_by_id(cursor, node);
        if (has_next(iterator)) {
            Node *node_iter = (Node *) next(iterator);
            (*nodes_rel)[i] = create_node_copy(node_iter);
            free_node(node_iter);
        } else {
            (*nodes_rel)[i] = NULL;
        }
        free_iter(iterator);
    }
    free_node(node);
}

void find_properties_for_nodes(Cursor *cursor, int nodes_count, Node **nodes, Property ***properties_n) {
    Property *prop = (Property*) malloc(PROPERTY_SIZE);
    prop->value = malloc(CHAR_SIZE);

    for (int i = 0; i < nodes_count; i++) {
        (*properties_n)[i] = NULL;
    }
    
    for (int i = 0; i < nodes_count; i++) {
        Node *nd = nodes[i];
        prop->subject_id = nd->id;
        for (uint32_t j = 0; j < NAME_TYPE_SIZE; j++) (prop->subject_type)[i] = '\0';
        strcpy(prop->subject_type, nd->type);
        strcpy(prop->type, "text");
        
        Iterator *iterator = select_property_by_subject(cursor, prop);
        while (has_next(iterator)) {
            Property *prop_iter = (Property *) next(iterator);
            
            if (strcmp(prop_iter->type, "text") == 0) {
                (*properties_n)[i] = create_property_copy(prop_iter);
                break;
            }
            
            free_node(prop_iter);
        }
        //  else {
        //     (*properties_n)[i] = NULL;
        // }
        free_iter(iterator);
    }
    free_property(prop);
}

void find_properties_for_request(Cursor *cursor, Node *nd, int *properties_count, Property ***properties, RequestMessage *request) {
    EntityIterator *entity_iterator_prop = select_properties_by_node(cursor, nd);

    while (entity_iterator_prop != NULL && entity_has_next(entity_iterator_prop)) {
        Property *pr = entity_next(entity_iterator_prop);
        if (is_element_in_array(request->properties, request->n_properties, pr->type)) {
            (*properties_count)++;
            *properties = (Property **) realloc(*properties, *properties_count * sizeof(Property*));
            (*properties)[*properties_count - 1] = create_property_copy(pr);
        }
        free_property(pr);
    }
    free_entity_iter(entity_iterator_prop);
}
