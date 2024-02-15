#include "../include/server/entity_handler.h"
#include "../include/data/entity.h"
#include "../include/server/convertor.h"
#include "../include/server/validator.h"

ResponceMessage *handle_entity_request(RequestMessage *request, Cursor *cursor) {
    ResponceMessage *responce = (ResponceMessage *) malloc(sizeof(ResponceMessage));
    responce_message__init(responce);

    if (!is_valid_entity_request(request)) {
        responce->message = "Not enougth parameters for entity";
        responce->status = 400;
        return responce;    
    }

    Entity *entity = convert_request_to_entity(request);
    bool is_success = false;
    switch (request->operation) {
        case OPERATION_PROTO__CREATE_ENTITY:
            is_success = create_entity(cursor, entity);
            break;
        case OPERATION_PROTO__DELETE_ENTITY:
            is_success = delete_entity(cursor, entity);
            break;
        default:
            is_success = false;
    }

    free(entity);
    if (is_success) {
        responce->message = "Successfuly executed operation for entity";
        responce->status = 200;
    } else {
        responce->message = "Error occured while executing operation for entity";
        responce->status = 400;
    }
    
    return responce;
}
