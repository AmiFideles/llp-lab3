/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: propertyresponce.proto */

#ifndef PROTOBUF_C_propertyresponce_2eproto__INCLUDED
#define PROTOBUF_C_propertyresponce_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "valuetype.pb-c.h"

typedef struct _PropertyResponce PropertyResponce;


/* --- enums --- */


/* --- messages --- */

struct  _PropertyResponce
{
  ProtobufCMessage base;
  ValueTypeProto value_type;
  char *type;
  char *value;
};
#define PROPERTY_RESPONCE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&property_responce__descriptor) \
    , VALUE_TYPE_PROTO__INT, NULL, NULL }


/* PropertyResponce methods */
void   property_responce__init
                     (PropertyResponce         *message);
size_t property_responce__get_packed_size
                     (const PropertyResponce   *message);
size_t property_responce__pack
                     (const PropertyResponce   *message,
                      uint8_t             *out);
size_t property_responce__pack_to_buffer
                     (const PropertyResponce   *message,
                      ProtobufCBuffer     *buffer);
PropertyResponce *
       property_responce__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   property_responce__free_unpacked
                     (PropertyResponce *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*PropertyResponce_Closure)
                 (const PropertyResponce *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor property_responce__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_propertyresponce_2eproto__INCLUDED */
