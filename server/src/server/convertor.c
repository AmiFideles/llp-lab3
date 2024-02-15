#include "../include/server/convertor.h"
#include "data/enums.h"
#include <stdlib.h>
#include <string.h>
#include "../include/utils/string_utils.h"
#include "data/property.h"


TypeOfElement convert_type_of_element(TypeOfElementProto type) {
    switch (type) {
        case TYPE_OF_ELEMENT_PROTO__NODE:
            return NODE;
        case TYPE_OF_ELEMENT_PROTO__PROPERTY:
            return PROPERTY;
        case TYPE_OF_ELEMENT_PROTO__RELATIONSHIP:
            return RELATIONSHIP;
        default:
            return NODE;
    }
}

ValueType convert_value_type(ValueTypeProto type) {
    switch (type) {
        case VALUE_TYPE_PROTO__INT:
            return INT;
        case VALUE_TYPE_PROTO__STRING:
            return STRING;
        case VALUE_TYPE_PROTO__VOID:
            return VOID;
        case VALUE_TYPE_PROTO__BOOL:
            return BOOL;
        default:
            return VOID;
    }
}

ValueTypeProto convert_value_type_proto(ValueType type) {
    switch (type) {
        case INT:
            return VALUE_TYPE_PROTO__INT;
        case STRING:
            return VALUE_TYPE_PROTO__STRING;
        case VOID:
            return VALUE_TYPE_PROTO__VOID;
        case BOOL:
            return VALUE_TYPE_PROTO__BOOL;
        default:
            return VALUE_TYPE_PROTO__VOID;
    }
}

Node *convert_to_node(NodeMessage *message) {
    Node *node = (Node *) malloc(NODE_SIZE);
    node->id = 0;
    node->name_length = strlen(message->name) + 1;
    node->name = string_copy(message->name);
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (node->type)[i] = '\0';
    strcpy(node->type, message->type);
    return node;
}

Relationship *convert_to_relationship(RelationshipMessage *message) {
    Relationship *relationship = (Relationship *) malloc(RELATIONSHIP_SIZE);
    relationship->id = 0;
    relationship->parent_id = message->parent_id;
    relationship->child_id = message->child_id;
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (relationship->type)[i] = '\0';
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (relationship->child_type)[i] = '\0';
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (relationship->parent_type)[i] = '\0';
    strcpy(relationship->type, message->type);
    strcpy(relationship->child_type, message->child_type);
    strcpy(relationship->parent_type, message->parent_type);

    return relationship;
}

Property *convert_to_property(PropertyMessage *message) {
    Property *property = (Property *) malloc(PROPERTY_SIZE);
    property->value_type = convert_value_type(message->value_type);
    property->subject_id = message->subject_id;
    property->value_length = strlen(message->value) + 1;
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (property->type)[i] = '\0';
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (property->subject_type)[i] = '\0';
    strcpy(property->type, message->type);
    strcpy(property->subject_type, message->subject_type);
    property->value = string_copy(message->value);

    return property;
}

Entity *convert_request_to_entity(RequestMessage *request) {
    Entity *entity = (Entity *) malloc(ENTITY_SIZE);
    for (int i = 0; i < NAME_TYPE_LENGTH + 1; i++) (entity->type)[i] = '\0';
    EntityMessage *entity_message = request->entity;
    entity->element_type = convert_type_of_element(entity_message->type_of_element);
    entity->value_type = convert_value_type(entity_message->value_type);
    strcpy(entity->type, entity_message->name);
    return entity;
}

Element *convert_request_to_element(RequestMessage *request) {
    Element *element = (Element *) malloc(sizeof(Element));
    switch (request->type) {
        case TYPE_OF_ELEMENT_PROTO__NODE:
            element->type = NODE;
            element->node = convert_to_node(request->node);
            break;
        case TYPE_OF_ELEMENT_PROTO__RELATIONSHIP:
            element->type = RELATIONSHIP;
            element->relationship = convert_to_relationship(request->relationship);
            break;
        case TYPE_OF_ELEMENT_PROTO__PROPERTY:
            element->type = PROPERTY;
            element->property = convert_to_property(request->property);
            break;
        default:
            return NULL;
    }
    return element;
}

SimpleNodeMessage *convert_node_to_responce(Node *nd) {
    SimpleNodeMessage *simple_node = malloc(sizeof(SimpleNodeMessage));
    simple_node_message__init(simple_node);

    simple_node->id = nd->id;
    simple_node->name = string_copy(nd->name);
    simple_node->type = string_copy(nd->type);    

    return simple_node;
}

RelationshipNodeResponce *convert_relationship_to_responce(Node *nd, Relationship *rel, Property *pr) {
    RelationshipNodeResponce *resp = malloc(sizeof(RelationshipNodeResponce));
    relationship_node_responce__init(resp);

    SimpleNodeMessage *simple_node_rel = malloc(sizeof(SimpleNodeMessage));
    simple_node_message__init(simple_node_rel);

    PropertyResponce *prop_n = malloc(sizeof(PropertyResponce));
    property_responce__init(prop_n);

    if (nd != NULL) {
        simple_node_rel->id = nd->id;
        simple_node_rel->name = string_copy(nd->name);
        simple_node_rel->type = string_copy(nd->type);
        resp->node = simple_node_rel;
    }
    if (pr != NULL) {
        prop_n->value_type = convert_value_type_proto(pr->value_type);
        prop_n->type = string_copy(pr->type);
        prop_n->value = string_copy(pr->value);
        resp->property = prop_n;
    }
    resp->relation_type = string_copy(rel->type);
    return resp;
}

PropertyResponce *convert_property_to_responce(Property *pr) {
    PropertyResponce *prop = malloc(sizeof(PropertyResponce));
    property_responce__init(prop);

    prop->value_type = convert_value_type_proto(pr->value_type);
    prop->type = string_copy(pr->type);
    prop->value = string_copy(pr->value);

    return prop;
}
