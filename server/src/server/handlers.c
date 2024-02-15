#include "../include/server/handlers.h"
#include "../include/server/entity_handler.h"
#include "../include/server/element_handler.h"

ResponceMessage *handle_request(RequestMessage *request, Cursor *cursor) {
    ResponceMessage *responce;
    if (request->type == TYPE_OF_ELEMENT_PROTO__ENTITY) {
        responce = handle_entity_request(request, cursor);
    } else {
        responce = handle_element_request(request, cursor);
    }

    return responce;
}

