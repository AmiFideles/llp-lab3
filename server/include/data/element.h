#pragma once

#include "data/enums.h"
#include "node.h"
#include "relationship.h"
#include "property.h"

typedef struct {
    TypeOfElement type;
    union {
        Node *node;
        Relationship *relationship;
        Property *property;
    };
} Element;
