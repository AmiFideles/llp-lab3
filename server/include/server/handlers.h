#pragma once

#include "../operations/common.h"
#include "../../binary/request.pb-c.h"
#include "../../binary/responce.pb-c.h"

ResponceMessage *handle_request(RequestMessage *request, Cursor *cursor);
