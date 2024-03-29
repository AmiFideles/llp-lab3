/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: responce.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "responce.pb-c.h"
void   responce_message__init
                     (ResponceMessage         *message)
{
  static const ResponceMessage init_value = RESPONCE_MESSAGE__INIT;
  *message = init_value;
}
size_t responce_message__get_packed_size
                     (const ResponceMessage *message)
{
  assert(message->base.descriptor == &responce_message__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t responce_message__pack
                     (const ResponceMessage *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &responce_message__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t responce_message__pack_to_buffer
                     (const ResponceMessage *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &responce_message__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
ResponceMessage *
       responce_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (ResponceMessage *)
     protobuf_c_message_unpack (&responce_message__descriptor,
                                allocator, len, data);
}
void   responce_message__free_unpacked
                     (ResponceMessage *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &responce_message__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor responce_message__field_descriptors[4] =
{
  {
    "status",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(ResponceMessage, status),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "message",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(ResponceMessage, message),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "node",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(ResponceMessage, node),
    &node_responce__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "iterator",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(ResponceMessage, iterator),
    &iterator_message__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned responce_message__field_indices_by_name[] = {
  3,   /* field[3] = iterator */
  1,   /* field[1] = message */
  2,   /* field[2] = node */
  0,   /* field[0] = status */
};
static const ProtobufCIntRange responce_message__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor responce_message__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ResponceMessage",
  "ResponceMessage",
  "ResponceMessage",
  "",
  sizeof(ResponceMessage),
  4,
  responce_message__field_descriptors,
  responce_message__field_indices_by_name,
  1,  responce_message__number_ranges,
  (ProtobufCMessageInit) responce_message__init,
  NULL,NULL,NULL    /* reserved[123] */
};
