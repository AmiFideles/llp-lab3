#pragma once

#include "../data/property.h"
#include "../data/element.h"
#include "../binary/request.pb-c.h"
#include "../binary/relationshipnoderesponce.pb-c.h"
#include "../binary/propertyresponce.pb-c.h"

TypeOfElement convert_type_of_element(TypeOfElementProto type);
ValueType convert_value_type(ValueTypeProto type);
ValueTypeProto convert_value_type_proto(ValueType type);

Node *convert_to_node(NodeMessage *message);
Relationship *convert_to_relationship(RelationshipMessage *message);
Property *convert_to_property(PropertyMessage *message);
Entity *convert_request_to_entity(RequestMessage *request);
Element *convert_request_to_element(RequestMessage *request);

SimpleNodeMessage *convert_node_to_responce(Node *nd);
RelationshipNodeResponce *convert_relationship_to_responce(Node *nd, Relationship *rel, Property *pr);
PropertyResponce *convert_property_to_responce(Property *pr);
