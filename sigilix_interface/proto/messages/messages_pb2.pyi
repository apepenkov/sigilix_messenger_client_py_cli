from typing import Any, bytes, Optional, Union
from ..users import users_pb2 as users

class InitChatFromInitializerRequest:
    target_user_id: int
    def __init__(self, target_user_id: int): ...

class InitChatFromInitializerResponse:
    chat_id: int
    def __init__(self, chat_id: int): ...

class InitChatFromInitializerNotification:
    chat_id: int
    initializer_user_info: users.PublicUserInfo
    def __init__(self, chat_id: int, initializer_user_info: users.PublicUserInfo): ...

class InitChatFromReceiverRequest:
    chat_id: int
    def __init__(self, chat_id: int): ...

class InitChatFromReceiverResponse:
    chat_id: int
    def __init__(self, chat_id: int): ...

class InitChatFromReceiverNotification:
    chat_id: int
    receiver_user_info: users.PublicUserInfo
    def __init__(self, chat_id: int, receiver_user_info: users.PublicUserInfo): ...

class UpdateChatRsaKeyRequest:
    chat_id: int
    rsa_public_key: bytes
    def __init__(self, chat_id: int, rsa_public_key: bytes): ...

class UpdateChatRsaKeyResponse:
    chat_id: int
    def __init__(self, chat_id: int): ...

class UpdateChatRsaKeyNotification:
    chat_id: int
    user_id: int
    rsa_public_key: bytes
    def __init__(self, chat_id: int, user_id: int, rsa_public_key: bytes): ...

class SendMessageRequest:
    chat_id: int
    encrypted_message: bytes
    message_ecdsa_signature: bytes
    def __init__(
        self,
        chat_id: int,
        encrypted_message: bytes,
        message_ecdsa_signature: bytes,
    ): ...

class SendMessageResponse:
    chat_id: int
    message_id: int
    def __init__(self, chat_id: int, message_id: int): ...

class SendMessageNotification:
    chat_id: int
    message_id: int
    sender_user_id: int
    encrypted_message: bytes
    message_ecdsa_signature: bytes
    def __init__(
        self,
        chat_id: int,
        message_id: int,
        sender_user_id: int,
        encrypted_message: bytes,
        message_ecdsa_signature: bytes,
    ): ...

class SendFileRequest:
    chat_id: int
    encrypted_file: bytes
    encrypted_mime_type: bytes
    file_ecdsa_signature: bytes
    def __init__(
        self,
        chat_id: int,
        encrypted_file: bytes,
        encrypted_mime_type: bytes,
        file_ecdsa_signature: bytes,
    ): ...

class SendFileResponse:
    chat_id: int
    message_id: int
    def __init__(self, chat_id: int, message_id: int): ...

class SendFileNotification:
    chat_id: int
    message_id: int
    sender_user_id: int
    encrypted_file: bytes
    encrypted_mime_type: bytes
    file_ecdsa_signature: bytes
    def __init__(
        self,
        chat_id: int,
        message_id: int,
        sender_user_id: int,
        encrypted_file: bytes,
        encrypted_mime_type: bytes,
        file_ecdsa_signature: bytes,
    ): ...

class SubscriptionRequest:
    def __init__(self): ...

class IncomingNotification:
    init_chat_from_initializer_notification: Optional[InitChatFromInitializerNotification]
    init_chat_from_receiver_notification: Optional[InitChatFromReceiverNotification]
    update_chat_rsa_key_notification: Optional[UpdateChatRsaKeyNotification]
    send_message_notification: Optional[SendMessageNotification]
    send_file_notification: Optional[SendFileNotification]

    ecdsa_signature: bytes
    def __init__(
        self,
    ): ...



class GetNotificationsRequest:
    limit: int
    def __init__(self, limit: int): ...

class GetNotificationsResponse:
    notifications: list[IncomingNotification]
    def __init__(self, notifications: list[IncomingNotification]): ...

class MessageServiceStub:
    def InitChatFromInitializer(
        self, request: InitChatFromInitializerRequest, context: Any
    ) -> InitChatFromInitializerResponse: ...
    def InitChatFromReceiver(
        self, request: InitChatFromReceiverRequest, context: Any
    ) -> InitChatFromReceiverResponse: ...
    def UpdateChatRsaKey(
        self, request: UpdateChatRsaKeyRequest, context: Any
    ) -> UpdateChatRsaKeyResponse: ...
    def SendMessage(
        self, request: SendMessageRequest, context: Any
    ) -> SendMessageResponse: ...
    def SendFile(self, request: SendFileRequest, context: Any) -> SendFileResponse: ...
    def GetNotifications(
        self, request: GetNotificationsRequest, context: Any
    ) -> GetNotificationsResponse: ...
    def SubscribeToIncomingNotifications(
        self, request: SubscriptionRequest, context: Any
    ) -> IncomingNotification: ...
