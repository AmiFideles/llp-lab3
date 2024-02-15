#include "parser_ast.h"
#include "ast.h"
#include "entity.pb-c.h"
#include "filter.pb-c.h"
#include "node.pb-c.h"
#include "operation.pb-c.h"
#include "property.pb-c.h"
#include "relationship.pb-c.h"
#include "request.pb-c.h"
#include "typeelement.pb-c.h"
#include "node.pb-c.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../utils/string_utils.h"
#include "../utils/io_utils.h"
#include "valuetype.pb-c.h"

OperationProto get_operation_type(Node *node) {
    Node *type = node->left->left->left->left->left->left;
    if (strcmp(type->value.str_val, "CreateNode") == 0) {
        return OPERATION_PROTO__CREATE_NODE;
    }
    if (strcmp(type->value.str_val, "UpdateNode") == 0) {
        return OPERATION_PROTO__UPDATE_NODE;
    }
    if (strcmp(type->value.str_val, "SelectNode") == 0) {
        return OPERATION_PROTO__SELECT_NODE;
    }
    if (strcmp(type->value.str_val, "DeleteNode") == 0) {
        return OPERATION_PROTO__DELETE_NODE;
    }
    if (strcmp(type->value.str_val, "CreateEntity") == 0) {
        return OPERATION_PROTO__CREATE_ENTITY;
    }
    if (strcmp(type->value.str_val, "DeleteEntity") == 0) {
        return OPERATION_PROTO__DELETE_ENTITY;
    }
    exit_with_error("Invalid operation type: %s\n", type->value.str_val);
    exit(1);
}

FieldProto convert_to_field(char *field) {
    if (strcmp(field, "id") == 0) {
        return FIELD_PROTO__ID;
    }
    if (strcmp(field, "name") == 0) {
        return FIELD_PROTO__NAME;
    }
    exit_with_error("Invalid field: %s\n", field);
    exit(1);
}

CompareTypeProto convert_to_compare_type(char *type) {
    (void) type;
    return COMPARE_TYPE_PROTO__ALL;
}

void find_selections(Node *node, FilterMessage *element) {
    if (node == NULL) {
        return;
    }

    find_selections(node->right, element);
    find_selections(node->left, element);

    if (node->type != NAME_DEFINITION) return;

    Node *field = node->left;
    Node *value = node->right->left;
    Node *value_type = node->right;
    if (strcmp(field->value.str_val, "type") == 0) {
        element->type_element = create_buff_string(value->value.str_val);
    
    } else {
        element->field = convert_to_field(field->value.str_val);
        if (value_type->type == VAR_VALUE) {
            element->value = create_buff_string(value->value.str_val);
        } else if (value_type->type == VALUE) {
            element->value = cut_quotes(value->value.str_val);
        } else {
            element->value = int_to_string(value->value.int_val);
        }
    }
}

FilterMessage *get_filter(Node *node) {
    Node *selection_set = node->left->left->left->right->left->right;
    FilterMessage *f = (FilterMessage *) malloc(sizeof(FilterMessage));
    filter_message__init(f);

    find_selections(selection_set, f);
    f->type = convert_to_compare_type("");

    return f;
}

TypeOfElementProto get_type_element (const char *str) {
    if (strcmp(str, "node") == 0) {
        return TYPE_OF_ELEMENT_PROTO__NODE;
    } else if (strcmp(str, "relationship") == 0) {
        return TYPE_OF_ELEMENT_PROTO__RELATIONSHIP;
    } else if (strcmp(str, "property") == 0) {
        return TYPE_OF_ELEMENT_PROTO__PROPERTY;
    } else {
        exit_with_error("Invalid string for TypeOfElement: %s\n", str);
        exit(1);
    }
}

ValueTypeProto get_value_type(const char *str) {
    if (strcmp(str, "int") == 0) {
        return VALUE_TYPE_PROTO__INT;
    } else if (strcmp(str, "float") == 0) {
        return VALUE_TYPE_PROTO__FLOAT;
    } else if (strcmp(str, "string") == 0) {
        return VALUE_TYPE_PROTO__STRING;
    } else if (strcmp(str, "bool") == 0) {
        return VALUE_TYPE_PROTO__BOOL;
    } else if (strcmp(str, "void") == 0) {
        return VALUE_TYPE_PROTO__VOID;
    } else {
        exit_with_error("Invalid string for ValueType: %s\n", str);
        exit(1);
    }
}

void construct_entity(Node *node, EntityMessage *entity) {
    if (node == NULL) {
        return;
    }

    construct_entity(node->right, entity);
    construct_entity(node->left, entity);

    if (node->type != JSON_ELEMENT) return;

    Node *field = node->left->left;
    Node *value = node->right->left;
    if (strcmp(field->value.str_val, "type_of_element") == 0) {
        entity->type_of_element = get_type_element(value->value.str_val);
    } else if (strcmp(field->value.str_val, "value_type") == 0) {
        entity->value_type = get_value_type(value->value.str_val);
    } else if (strcmp(field->value.str_val, "name") == 0) {
        entity->name = create_buff_string(value->value.str_val);
    }
}

TypeOfElementProto convert_to_element_type(const char *str) {
    if (strcmp(str, "node") == 0) {
        return TYPE_OF_ELEMENT_PROTO__NODE;
    }
    if (strcmp(str, "relationship") == 0) {
        return TYPE_OF_ELEMENT_PROTO__RELATIONSHIP;
    }
    if (strcmp(str, "property") == 0) {
        return TYPE_OF_ELEMENT_PROTO__PROPERTY;
    }
    exit_with_error("Invalid element type: %s\n", str);
    exit(1);
}

void construct_property(Node *node, PropertyMessage *element) {
    if (node == NULL) {
        return;
    }

    construct_property(node->right, element);
    construct_property(node->left, element);

    if (node->type != JSON_ELEMENT) return;

    Node *field = node->left->left;
    Node *value = node->right->left;
    Node *value_type = node->right;
    if (strcmp(field->value.str_val, "value_type") == 0) {
        element->value_type = get_value_type(value->value.str_val);
    
    } else if (strcmp(field->value.str_val, "subject_id") == 0) {
        element->subject_id = value->value.int_val;

    } else if (strcmp(field->value.str_val, "type") == 0) {
        element->type = create_buff_string(value->value.str_val);
    
    } else if (strcmp(field->value.str_val, "subject_type") == 0) {
        element->subject_type = create_buff_string(value->value.str_val);
    
    } else if (strcmp(field->value.str_val, "value") == 0) {
        if (value_type->type == VAR_VALUE) {
            element->value = create_buff_string(value->value.str_val);
        } else if (value_type->type == VALUE) {
            element->value = cut_quotes(value->value.str_val);
        } else {
            element->value = int_to_string(value->value.int_val);
        }
    }
}

void construct_relationship(Node *node, RelationshipMessage *element) {
    if (node == NULL) {
        return;
    }

    construct_relationship(node->right, element);
    construct_relationship(node->left, element);

    if (node->type != JSON_ELEMENT) return;

    Node *field = node->left->left;
    Node *value = node->right->left;
    if (strcmp(field->value.str_val, "parent_id") == 0) {
        element->parent_id = value->value.int_val;
    
    } else if (strcmp(field->value.str_val, "child_id") == 0) {
        element->child_id = value->value.int_val;
    
    } else if (strcmp(field->value.str_val, "type") == 0) {
        element->type = create_buff_string(value->value.str_val);
    
    } else if (strcmp(field->value.str_val, "parent_type") == 0) {
        element->parent_type = create_buff_string(value->value.str_val);

    } else if (strcmp(field->value.str_val, "child_type") == 0) {
        element->child_type = create_buff_string(value->value.str_val);
    
    }
}

void construct_node(Node *node, NodeMessage *element) {
    if (node == NULL) {
        return;
    }

    construct_node(node->right, element);
    construct_node(node->left, element);

    if (node->type != JSON_ELEMENT) return;

    Node *field = node->left->left;
    Node *value = node->right->left;
    Node *value_type = node->right;
    if (strcmp(field->value.str_val, "type") == 0) {
        element->type = create_buff_string(value->value.str_val);
    
    } else if (strcmp(field->value.str_val, "name") == 0) {
        if (value_type->type == VAR_VALUE) {
            element->name = create_buff_string(value->value.str_val);
        } else if (value_type->type == VALUE) {
            element->name = cut_quotes(value->value.str_val);
        } else {
            element->name = int_to_string(value->value.int_val);
        }
    }
}

void construct_element(Node* node, RequestMessage *request, TypeOfElementProto type) {
    switch (type) {
        case TYPE_OF_ELEMENT_PROTO__NODE: {
            NodeMessage *element = (NodeMessage *) malloc(sizeof(NodeMessage));
            node_message__init(element);
            construct_node(node, element);
            
            request->node = element;//TODO: test for update
            break;
        }
        case TYPE_OF_ELEMENT_PROTO__RELATIONSHIP: {
            RelationshipMessage *element = (RelationshipMessage *) malloc(sizeof(RelationshipMessage));
            relationship_message__init(element);
            construct_relationship(node, element);

            request->relationship = element;
            break;
        }
        case TYPE_OF_ELEMENT_PROTO__PROPERTY: {
            PropertyMessage *element = (PropertyMessage *) malloc(sizeof(PropertyMessage));
            property_message__init(element);
            construct_property(node, element);

            request->property = element;
            break;
        }
        default:
            exit_with_error("Invalid type for consturct element\n");
            break;
    }
}

TypeOfElementProto get_element_type_for_query(Node *node) {
    Node *type_def = node->left->left->left->right->left->left->left->left;
    char *type = type_def->value.str_val;
    if (strcmp(type, "createNode") == 0 ||
        strcmp(type, "deleteNode") == 0 ||
        strcmp(type, "updateNode") == 0) {
        return TYPE_OF_ELEMENT_PROTO__NODE;
    }
    if (strcmp(type, "createProperty") == 0 ||
        strcmp(type, "deleteProperty") == 0 ||
        strcmp(type, "updateProperty") == 0) {
        return TYPE_OF_ELEMENT_PROTO__PROPERTY;
    }
    if (strcmp(type, "createRelationship") == 0 ||
        strcmp(type, "deleteRelationship") == 0 ||
        strcmp(type, "updateRelationship") == 0) {
        return TYPE_OF_ELEMENT_PROTO__RELATIONSHIP;
    }
    exit_with_error("Invalid type of element for query: %s\n", type);
    exit(1);
}

void collect_fields(Node* node, char*** fields, int* fields_count, const char *exclude) {
    if (node == NULL) {
        return;
    }

    if (node->type == FIELD && strcmp(exclude, node->value.str_val) != 0) {
        (*fields_count)++;
        *fields = (char**) realloc(*fields, *fields_count * sizeof(char*));
        (*fields)[*fields_count - 1] = string_copy(node->value.str_val);
    }

    collect_fields(node->left, fields, fields_count, exclude);
    collect_fields(node->right, fields, fields_count, exclude);
}

Node *find_join_parameters(Node *node, const char *join) {
    Node *nd = node;
    if (nd == NULL || nd->left == NULL || nd->left->left == NULL || nd->left->left->left == NULL) {
        return NULL;
    }
    
    if (nd->left->left->left->type == FIELD && strcmp(nd->left->left->left->value.str_val, join) == 0) {
        return nd;
    }
    
    Node *left = find_join_parameters(nd->left, join);
    if (left == NULL) return find_join_parameters(nd->right, join);
    return left;
}

RequestMessage *parse_ast(Node *node) {
    OperationProto operation;
    TypeOfElementProto type;
    FilterMessage *filter;
    EntityMessage *entity;

    RequestMessage *request = (RequestMessage *) malloc(sizeof(RequestMessage));
    request_message__init(request);

    operation = get_operation_type(node);
    switch (operation) {
        case OPERATION_PROTO__CREATE_ENTITY:
        case OPERATION_PROTO__DELETE_ENTITY:
            type = TYPE_OF_ELEMENT_PROTO__ENTITY;
            break;
        case OPERATION_PROTO__SELECT_NODE:
            type = TYPE_OF_ELEMENT_PROTO__NODE;
            break;
        default:
            type = get_element_type_for_query(node);
    }

    request->operation = operation;
    request->type = type;

    if (operation == OPERATION_PROTO__DELETE_ENTITY ||
        operation == OPERATION_PROTO__SELECT_NODE ||
        operation == OPERATION_PROTO__UPDATE_NODE ||
        operation == OPERATION_PROTO__DELETE_NODE) {
        
        filter = get_filter(node);
        request->filter = filter;
    }

    if (operation == OPERATION_PROTO__CREATE_ENTITY ||
        operation == OPERATION_PROTO__DELETE_ENTITY) {

        entity = (EntityMessage *) malloc(sizeof(EntityMessage));
        entity_message__init(entity);
        construct_entity(node->right, entity);
        request->entity = entity;
    } else if (operation != OPERATION_PROTO__SELECT_NODE) {
        construct_element(node->right, request, type);
    }

    if (operation == OPERATION_PROTO__SELECT_NODE) {
        
        char** relationships = NULL;
        int relationships_count = 0;

        Node *rel = find_join_parameters(node, "relationships");
        if (rel != NULL) {
            collect_fields(rel, &relationships, &relationships_count, "relationships");
            request->n_relationships = relationships_count;
            request->relationships = relationships;
        }

        char** properties = NULL;
        int properties_count = 0;

        Node *prop = find_join_parameters(node, "properties");
        if (prop != NULL) {
            collect_fields(prop, &properties, &properties_count, "properties");
            request->n_properties = properties_count;
            request->properties = properties;
        }
    }
    return request;
}
