#include "../include/server/element_handler.h"
#include "../include/server/find_element_handler.h"
#include "../include/operations/crud_methods.h"
#include "data/enums.h"
#include "data/property.h"
#include <string.h>

bool handle_create_element(Cursor *cursor, Element *element) {
    bool status;
    switch (element->type) {
        case NODE:
            status = create_node(cursor, element->node);
            free_node(element->node);
            break;
        case RELATIONSHIP:
            status = create_relationship(cursor, element->relationship);
            free_relationship(element->relationship);
            break;
        case PROPERTY:
            status = create_property(cursor, element->property);
            free_property(element->property);
            break;
    }
    free(element);
    return status;
}

bool handle_update_element(Cursor *cursor, FilterMessage *filter, TypeOfElement type, Element *element) {
    bool status;
    switch (type) {
        case NODE: {
            Node nd = {atoi(filter->value), 0, "", ""};
            strcpy(nd.type, filter->type_element);
            status = update_node_by_id(cursor, &nd, element->node);
            free_node(element->node);
            break;
        }
        case RELATIONSHIP: {
            Relationship rl = {0, atoi(filter->value), 0, "", "", ""};
            strcpy(rl.type, filter->type_element);
            status = update_relationship_by_parent(cursor, &rl, element->relationship);
            free_relationship(element->relationship);
            break;
        }
        case PROPERTY: {
            Property pr = {0, atoi(filter->value), 0, "", "", ""};
            strcpy(pr.type, filter->type_element);
            status = update_property_by_subject(cursor, &pr, element->property);
            free_property(element->property);
            break;
        }
    }
    free(element);
    return status;
}

ResponceMessage *handle_select_element(Cursor *cursor, RequestMessage *request) {
    ResponceMessage *responce = (ResponceMessage *) malloc(sizeof(ResponceMessage));
    responce_message__init(responce);
    Iterator *iter = NULL;

    Node *nd = find_node_from_request(cursor, request, &iter);
    if (nd == NULL) {
        responce->status = 404;
        responce->message = "Not found such element";
        return responce;
    }

    IteratorMessage *iterator_message = (IteratorMessage *) malloc(sizeof(IteratorMessage));
    iterator_message__init(iterator_message);
    iterator_message->offset = *(iter->offset_);
    iterator_message->read_block = *(iter->read_block_);
    free_iter(iter);

    Relationship** relationships = NULL;
    int relationships_count = 0;
    find_relationship_for_request(cursor, nd, &relationships_count, &relationships, request);

    Node **nodes_rel = (Node **) malloc(relationships_count * sizeof(Node*));
    find_nodes_by_relationships(cursor, relationships_count, relationships, &nodes_rel);

    Property **properties_n = (Property **) malloc(relationships_count * sizeof(Property*));
    find_properties_for_nodes(cursor, relationships_count, nodes_rel, &properties_n);

    Property **properties = NULL;
    int properties_count = 0;
    find_properties_for_request(cursor, nd, &properties_count, &properties, request);

    NodeResponce *node_responce = malloc(sizeof(NodeResponce));
    node_responce__init(node_responce);
    
    node_responce->simple_node = convert_node_to_responce(nd);

    RelationshipNodeResponce **relationships_responce = malloc(relationships_count * sizeof(RelationshipNodeResponce*));
    for (int i = 0; i < relationships_count; i++) {
        relationships_responce[i] = convert_relationship_to_responce(nodes_rel[i], relationships[i], properties_n[i]);
    }

    PropertyResponce **properties_responce = malloc(relationships_count * sizeof(PropertyResponce*));
    for (int i = 0; i < properties_count; i++) {
        properties_responce[i] = convert_property_to_responce(properties[i]);
    }

    node_responce->n_relationships = relationships_count;
    node_responce->relationships = relationships_responce;
    node_responce->n_properties = properties_count;
    node_responce->properties = properties_responce;

    responce->node = node_responce;
    responce->iterator = iterator_message;
    responce->status = 201;
    responce->message = "Find element";

    return responce;
}

bool handle_delete_element(Cursor * cursor, FilterMessage *filter, TypeOfElement type) {
    bool status;
    switch (type) {
        case NODE: {
            Node nd = {atoi(filter->value), 0, "", ""};
            strcpy(nd.type, filter->type_element);
            status = delete_node_by_id(cursor, &nd);
            break;
        }
        case RELATIONSHIP: {
            Relationship rl = {0, atoi(filter->value), 0, "", "", ""};
            strcpy(rl.type, filter->type_element);
            status = delete_relationship_by_parent(cursor, &rl);
            break;
        }
        case PROPERTY: {
            Property pr = {0, atoi(filter->value), 0, "", "", ""};
            strcpy(pr.type, filter->type_element);
            status = delete_property_by_subject(cursor, &pr);
            break;
        }
    }
    return status;
}

ResponceMessage *handle_element_request(RequestMessage *request, Cursor *cursor) {
    ResponceMessage *responce = (ResponceMessage *) malloc(sizeof(ResponceMessage));
    responce_message__init(responce);

    if (!is_valid_element_request(request)) {
        responce->message = "Not enougth parameters for entity";
        responce->status = 400;
        return responce;    
    }

    bool is_success = false;
    switch (request->operation) {
        case OPERATION_PROTO__CREATE_NODE: {
            Element *element = convert_request_to_element(request);
            is_success = handle_create_element(cursor, element);
            break;
        }
        case OPERATION_PROTO__UPDATE_NODE: {
            Element *element = convert_request_to_element(request); 
            is_success = handle_update_element(cursor, request->filter, convert_type_of_element(request->type), element);
            break;
        }
        case OPERATION_PROTO__SELECT_NODE: {
            ResponceMessage *select_responce = handle_select_element(cursor, request);
            return select_responce;
            break;
        }
        case OPERATION_PROTO__DELETE_NODE:
            is_success = handle_delete_element(cursor, request->filter, convert_type_of_element(request->type));
            break;
        default:
            is_success  = false;
    }

    if (is_success) {
        responce->message = "Successfuly executed operation";
        responce->status = 200;
    } else {
        responce->message = "Error occured while executing operation";
        responce->status = 400;
    }
    
    return responce; 
}
