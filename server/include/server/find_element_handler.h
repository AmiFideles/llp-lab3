#pragma once

#include "data/node.h"
#include "data/iterator.h"
#include "data/property.h"
#include "data/relationship.h"
#include "../../binary/request.pb-c.h"

Node *find_node_from_request(Cursor *cursor, RequestMessage *request, Iterator **iter);
void find_relationship_for_request(Cursor *cursor, Node *nd, int *relationships_count, Relationship ***relationships, RequestMessage *request);
void find_nodes_by_relationships(Cursor *cursor, int relationships_count, Relationship **relationships, Node ***nodes_rel);
void find_properties_for_request(Cursor *cursor, Node *nd, int *properties_count, Property ***properties, RequestMessage *request);
void find_properties_for_nodes(Cursor *cursor, int nodes_count, Node **nodes, Property ***properties_n);
