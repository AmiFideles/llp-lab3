#pragma once

#include "../include/server/convertor.h"
#include "../include/server/validator.h"
#include "../include/server/handlers.h"

bool handle_create_element(Cursor *, Element *);
bool handle_update_element(Cursor *, FilterMessage *, TypeOfElement, Element *);
ResponceMessage *handle_select_element(Cursor *cursor, RequestMessage *request);
bool handle_delete_element(Cursor * cursor, FilterMessage *filter, TypeOfElement type);
ResponceMessage *handle_element_request(RequestMessage *request, Cursor *cursor);
