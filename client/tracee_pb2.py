# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tracee.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='tracee.proto',
  package='tracee',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x0ctracee.proto\x12\x06tracee\"\x16\n\x05Trace\x12\r\n\x05\x65vent\x18\x01 \x01(\t\"\x19\n\x06Result\x12\x0f\n\x07message\x18\x01 \x01(\t2:\n\x06Tracee\x12\x30\n\x0bRecordTrace\x12\r.tracee.Trace\x1a\x0e.tracee.Result\"\x00(\x01\x62\x06proto3')
)




_TRACE = _descriptor.Descriptor(
  name='Trace',
  full_name='tracee.Trace',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='event', full_name='tracee.Trace.event', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=24,
  serialized_end=46,
)


_RESULT = _descriptor.Descriptor(
  name='Result',
  full_name='tracee.Result',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='message', full_name='tracee.Result.message', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=48,
  serialized_end=73,
)

DESCRIPTOR.message_types_by_name['Trace'] = _TRACE
DESCRIPTOR.message_types_by_name['Result'] = _RESULT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Trace = _reflection.GeneratedProtocolMessageType('Trace', (_message.Message,), {
  'DESCRIPTOR' : _TRACE,
  '__module__' : 'tracee_pb2'
  # @@protoc_insertion_point(class_scope:tracee.Trace)
  })
_sym_db.RegisterMessage(Trace)

Result = _reflection.GeneratedProtocolMessageType('Result', (_message.Message,), {
  'DESCRIPTOR' : _RESULT,
  '__module__' : 'tracee_pb2'
  # @@protoc_insertion_point(class_scope:tracee.Result)
  })
_sym_db.RegisterMessage(Result)



_TRACEE = _descriptor.ServiceDescriptor(
  name='Tracee',
  full_name='tracee.Tracee',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=75,
  serialized_end=133,
  methods=[
  _descriptor.MethodDescriptor(
    name='RecordTrace',
    full_name='tracee.Tracee.RecordTrace',
    index=0,
    containing_service=None,
    input_type=_TRACE,
    output_type=_RESULT,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_TRACEE)

DESCRIPTOR.services_by_name['Tracee'] = _TRACEE

# @@protoc_insertion_point(module_scope)
