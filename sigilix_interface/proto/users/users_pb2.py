# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: users.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0busers.proto\x12\x05users\"m\n\x0ePublicUserInfo\x12\x0f\n\x07user_id\x18\x01 \x01(\x04\x12\x18\n\x10\x65\x63\x64sa_public_key\x18\x02 \x01(\x0c\x12\x10\n\x08username\x18\x03 \x01(\t\x12\x1e\n\x16initial_rsa_public_key\x18\x04 \x01(\x0c\"a\n\x0fPrivateUserInfo\x12*\n\x0bpublic_info\x18\x01 \x01(\x0b\x32\x15.users.PublicUserInfo\x12\"\n\x1asearch_by_username_allowed\x18\x02 \x01(\x08\"N\n\x0cLoginRequest\x12\x1f\n\x17\x63lient_ecdsa_public_key\x18\x01 \x01(\x0c\x12\x1d\n\x15\x63lient_rsa_public_key\x18\x02 \x01(\x0c\"o\n\rLoginResponse\x12,\n\x0cprivate_info\x18\x01 \x01(\x0b\x32\x16.users.PrivateUserInfo\x12\x0f\n\x07user_id\x18\x02 \x01(\x04\x12\x1f\n\x17server_ecdsa_public_key\x18\x03 \x01(\x0c\"P\n\x18SetUsernameConfigRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\"\n\x1asearch_by_username_allowed\x18\x02 \x01(\x08\",\n\x19SetUsernameConfigResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\"+\n\x17SearchByUsernameRequest\x12\x10\n\x08username\x18\x01 \x01(\t\"F\n\x18SearchByUsernameResponse\x12*\n\x0bpublic_info\x18\x01 \x01(\x0b\x32\x15.users.PublicUserInfo2\xee\x01\n\x0bUserService\x12\x32\n\x05Login\x12\x13.users.LoginRequest\x1a\x14.users.LoginResponse\x12V\n\x11SetUsernameConfig\x12\x1f.users.SetUsernameConfigRequest\x1a .users.SetUsernameConfigResponse\x12S\n\x10SearchByUsername\x12\x1e.users.SearchByUsernameRequest\x1a\x1f.users.SearchByUsernameResponseB;Z9github.com/apepenkov/sigilix_messenger_server/proto/usersb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'users_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z9github.com/apepenkov/sigilix_messenger_server/proto/users'
  _globals['_PUBLICUSERINFO']._serialized_start=22
  _globals['_PUBLICUSERINFO']._serialized_end=131
  _globals['_PRIVATEUSERINFO']._serialized_start=133
  _globals['_PRIVATEUSERINFO']._serialized_end=230
  _globals['_LOGINREQUEST']._serialized_start=232
  _globals['_LOGINREQUEST']._serialized_end=310
  _globals['_LOGINRESPONSE']._serialized_start=312
  _globals['_LOGINRESPONSE']._serialized_end=423
  _globals['_SETUSERNAMECONFIGREQUEST']._serialized_start=425
  _globals['_SETUSERNAMECONFIGREQUEST']._serialized_end=505
  _globals['_SETUSERNAMECONFIGRESPONSE']._serialized_start=507
  _globals['_SETUSERNAMECONFIGRESPONSE']._serialized_end=551
  _globals['_SEARCHBYUSERNAMEREQUEST']._serialized_start=553
  _globals['_SEARCHBYUSERNAMEREQUEST']._serialized_end=596
  _globals['_SEARCHBYUSERNAMERESPONSE']._serialized_start=598
  _globals['_SEARCHBYUSERNAMERESPONSE']._serialized_end=668
  _globals['_USERSERVICE']._serialized_start=671
  _globals['_USERSERVICE']._serialized_end=909
# @@protoc_insertion_point(module_scope)