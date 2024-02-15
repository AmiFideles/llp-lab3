#include "ast.h"
#include "../binary/operation.pb-c.h"
#include "../binary/filter.pb-c.h"
#include "../binary/request.pb-c.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

OperationProto get_operation_type(Node *node);
FilterMessage *get_filter(Node *node);
FieldProto convert_to_field(char *field);
CompareTypeProto convert_to_compare_type(char *type);
void find_selections(Node *node, FilterMessage *element);
TypeOfElementProto get_type_element (const char *str);
ValueTypeProto get_value_type(const char *str);
void construct_entity(Node *node, EntityMessage *entity);
TypeOfElementProto convert_to_element_type(const char *str);
void collect_fields(Node* node, char*** fields, int* fields_count, const char *exclude);
Node *find_join_parameters(Node *node, const char *join);

RequestMessage *parse_ast(Node *node);
TypeOfElementProto get_element_type_for_query(Node *node) ;
void construct_element(Node* node, RequestMessage *request, TypeOfElementProto type) ;
void construct_node(Node *node, NodeMessage *element);
void construct_relationship(Node *node, RelationshipMessage *element);
void construct_property(Node *node, PropertyMessage *element);
