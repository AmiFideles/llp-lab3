#pragma once

#include "../operations/common.h"
#include "../data/node.h"
#include "../data/relationship.h"
#include "../data/property.h"
#include "../binary/request.pb-c.h"

bool is_valid_entity_request(RequestMessage *request);
bool is_valid_element_request(RequestMessage *request);
