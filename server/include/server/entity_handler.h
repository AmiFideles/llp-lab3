#pragma once

#include "data/cursor.h"
#include "../../binary/request.pb-c.h"
#include "../../binary/responce.pb-c.h"

ResponceMessage *handle_entity_request(RequestMessage *request, Cursor *cursor);
