import base64
import json
import typing
from abc import ABC, abstractmethod

from enum import Enum

some_notification = typing.Union[
    "InitChatFromInitializerNotification",
    "InitChatFromReceiverNotification",
    "UpdateChatRsaKeyNotification",
    "SendMessageNotification",
    "SendFileNotification",
]

some_bytes = typing.Union[bytes, "Base64Bytes"]


class NotificationType(Enum):
    INIT_CHAT_FROM_INITIALIZER = "InitChatFromInitializer"
    INIT_CHAT_FROM_RECEIVER = "InitChatFromReceiver"
    UPDATE_CHAT_RSA_KEY = "UpdateChatRsaKey"
    SEND_MESSAGE = "SendMessage"
    SEND_FILE = "SendFile"


# Base class
class AbstractStruct(ABC):
    @classmethod
    @abstractmethod
    def load(cls, data):
        pass

    @abstractmethod
    def dump(self):
        pass


# Base64Bytes class
class Base64Bytes:
    data: bytes

    def __init__(self, data: typing.Union[bytes, "Base64Bytes"]):
        if isinstance(data, Base64Bytes):
            self.data = data.data
        elif isinstance(data, bytes):
            self.data = data
        else:
            raise TypeError(f"expected bytes or Base64Bytes, got {type(data)}")

    @classmethod
    def load(cls, base64_string: str) -> "Base64Bytes":
        return cls(base64.b64decode(base64_string) if base64_string else b"")

    def dump(self) -> str:
        return base64.b64encode(self.data).decode()

    def __bytes__(self):
        return self.data


# PublicUserInfo class
class PublicUserInfo(AbstractStruct):
    user_id: int
    ecdsa_public_key: Base64Bytes
    username: str
    initial_rsa_public_key: Base64Bytes

    def __init__(
        self,
        user_id: int,
        ecdsa_public_key: some_bytes,
        username: str,
        initial_rsa_public_key: some_bytes,
    ):
        self.user_id = user_id
        self.ecdsa_public_key = Base64Bytes(ecdsa_public_key)
        self.username = username
        self.initial_rsa_public_key = Base64Bytes(initial_rsa_public_key)

    @classmethod
    def load(cls, data: dict) -> "PublicUserInfo":
        return cls(
            user_id=data.get("user_id", 0),
            ecdsa_public_key=Base64Bytes.load(data.get("ecdsa_public_key", "")),
            username=data.get("username", ""),
            initial_rsa_public_key=Base64Bytes.load(data.get("initial_rsa_public_key", "")),
        )

    def dump(self) -> dict:
        return {
            "user_id": self.user_id,
            "ecdsa_public_key": self.ecdsa_public_key.dump(),
            "username": self.username,
            "initial_rsa_public_key": self.initial_rsa_public_key.dump(),
        }


class PrivateUserInfo(AbstractStruct):
    public_info: PublicUserInfo
    search_by_username_allowed: bool

    def __init__(self, public_info: PublicUserInfo, search_by_username_allowed: bool):
        self.public_info = public_info
        self.search_by_username_allowed = search_by_username_allowed

    @classmethod
    def load(cls, data: dict) -> "PrivateUserInfo":
        return cls(
            public_info=PublicUserInfo.load(data["public_info"]),
            search_by_username_allowed=data["search_by_username_allowed"],
        )

    def dump(self) -> dict:
        return {
            "public_info": self.public_info.dump(),
            "search_by_username_allowed": self.search_by_username_allowed,
        }


# LoginRequest class
class LoginRequest(AbstractStruct):
    client_ecdsa_public_key: Base64Bytes
    client_rsa_public_key: Base64Bytes

    def __init__(
        self, client_ecdsa_public_key: some_bytes, client_rsa_public_key: some_bytes
    ):
        self.client_ecdsa_public_key = Base64Bytes(client_ecdsa_public_key)
        self.client_rsa_public_key = Base64Bytes(client_rsa_public_key)

    @classmethod
    def load(cls, data: dict) -> "LoginRequest":
        return cls(
            client_ecdsa_public_key=Base64Bytes.load(data["client_ecdsa_public_key"]),
            client_rsa_public_key=Base64Bytes.load(data["client_rsa_public_key"]),
        )

    def dump(self) -> dict:
        return {
            "client_ecdsa_public_key": self.client_ecdsa_public_key.dump(),
            "client_rsa_public_key": self.client_rsa_public_key.dump(),
        }


class LoginResponse(AbstractStruct):
    private_info: PrivateUserInfo
    user_id: int
    server_ecdsa_public_key: Base64Bytes

    def __init__(
        self,
        private_info: PrivateUserInfo,
        user_id: int,
        server_ecdsa_public_key: some_bytes,
    ):
        self.private_info = private_info
        self.user_id = user_id
        self.server_ecdsa_public_key = Base64Bytes(server_ecdsa_public_key)

    @classmethod
    def load(cls, data: dict) -> "LoginResponse":
        return cls(
            private_info=PrivateUserInfo.load(data["private_info"]),
            user_id=data["user_id"],
            server_ecdsa_public_key=Base64Bytes.load(data["server_ecdsa_public_key"]),
        )

    def dump(self) -> dict:
        return {
            "private_info": self.private_info.dump(),
            "user_id": self.user_id,
            "server_ecdsa_public_key": self.server_ecdsa_public_key.dump(),
        }


# SetUsernameConfigRequest class
class SetUsernameConfigRequest(AbstractStruct):
    username: str
    search_by_username_allowed: bool

    def __init__(self, username: str, search_by_username_allowed: bool):
        self.username = username
        self.search_by_username_allowed = search_by_username_allowed

    @classmethod
    def load(cls, data: dict) -> "SetUsernameConfigRequest":
        return cls(
            username=data["username"],
            search_by_username_allowed=data["search_by_username_allowed"],
        )

    def dump(self) -> dict:
        return {
            "username": self.username,
            "search_by_username_allowed": self.search_by_username_allowed,
        }


# SetUsernameConfigResponse class
class SetUsernameConfigResponse(AbstractStruct):
    success: bool

    def __init__(self, success: bool):
        self.success = success

    @classmethod
    def load(cls, data: dict) -> "SetUsernameConfigResponse":
        return cls(success=data["success"])

    def dump(self) -> dict:
        return {"success": self.success}


# SearchByUsernameRequest class
class SearchByUsernameRequest(AbstractStruct):
    username: str

    def __init__(self, username: str):
        self.username = username

    @classmethod
    def load(cls, data):
        return cls(username=data.get("username", ""))

    def dump(self):
        return {"username": self.username}


# SearchByUsernameResponse class
class SearchByUsernameResponse(AbstractStruct):
    public_info: PublicUserInfo

    def __init__(self, public_info: PublicUserInfo):
        self.public_info = public_info

    @classmethod
    def load(cls, data):
        return cls(public_info=PublicUserInfo.load(data.get("public_info", None) or dict()))

    def dump(self):
        return {"public_info": self.public_info.dump()}


# InitChatFromInitializerRequest class
class InitChatFromInitializerRequest(AbstractStruct):
    target_user_id: int

    def __init__(self, target_user_id: int):
        self.target_user_id = target_user_id

    @classmethod
    def load(cls, data: dict) -> "InitChatFromInitializerRequest":
        return cls(target_user_id=data["target_user_id"])

    def dump(self) -> dict:
        return {"target_user_id": self.target_user_id}


# InitChatFromInitializerResponse class
class InitChatFromInitializerResponse(AbstractStruct):
    chat_id: int

    def __init__(self, chat_id: int):
        self.chat_id = chat_id

    @classmethod
    def load(cls, data: dict) -> "InitChatFromInitializerResponse":
        return cls(chat_id=data["chat_id"])

    def dump(self) -> dict:
        return {"chat_id": self.chat_id}


# InitChatFromInitializerNotification class
class InitChatFromInitializerNotification(AbstractStruct):
    chat_id: int
    initializer_user_info: PublicUserInfo

    def __init__(self, chat_id: int, initializer_user_info: PublicUserInfo):
        self.chat_id = chat_id
        self.initializer_user_info = initializer_user_info

    @classmethod
    def load(cls, data: dict) -> "InitChatFromInitializerNotification":
        return cls(
            chat_id=data["chat_id"],
            initializer_user_info=PublicUserInfo.load(data["initializer_user_info"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "initializer_user_info": self.initializer_user_info.dump(),
        }


# InitChatFromReceiverRequest class
class InitChatFromReceiverRequest(AbstractStruct):
    chat_id: int

    def __init__(self, chat_id: int):
        self.chat_id = chat_id

    @classmethod
    def load(cls, data: dict) -> "InitChatFromReceiverRequest":
        return cls(chat_id=data["chat_id"])

    def dump(self) -> dict:
        return {"chat_id": self.chat_id}


# InitChatFromReceiverResponse class
class InitChatFromReceiverResponse(AbstractStruct):
    chat_id: int

    def __init__(self, chat_id: int):
        self.chat_id = chat_id

    @classmethod
    def load(cls, data: dict) -> "InitChatFromReceiverResponse":
        return cls(chat_id=data["chat_id"])

    def dump(self) -> dict:
        return {"chat_id": self.chat_id}


# InitChatFromReceiverNotification class
class InitChatFromReceiverNotification(AbstractStruct):
    chat_id: int
    receiver_user_info: PublicUserInfo

    def __init__(self, chat_id: int, receiver_user_info: PublicUserInfo):
        self.chat_id = chat_id
        self.receiver_user_info = receiver_user_info

    @classmethod
    def load(cls, data: dict) -> "InitChatFromReceiverNotification":
        return cls(
            chat_id=data["chat_id"],
            receiver_user_info=PublicUserInfo.load(data["receiver_user_info"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "receiver_user_info": self.receiver_user_info.dump(),
        }


class UpdateChatRsaKeyRequest(AbstractStruct):
    chat_id: int
    rsa_public_key: Base64Bytes

    def __init__(self, chat_id: int, rsa_public_key: some_bytes):
        self.chat_id = chat_id
        self.rsa_public_key = Base64Bytes(rsa_public_key)

    @classmethod
    def load(cls, data: dict) -> "UpdateChatRsaKeyRequest":
        return cls(
            chat_id=data["chat_id"],
            rsa_public_key=Base64Bytes.load(data["rsa_public_key"]),
        )

    def dump(self) -> dict:
        return {"chat_id": self.chat_id, "rsa_public_key": self.rsa_public_key.dump()}


# UpdateChatRsaKeyResponse class
class UpdateChatRsaKeyResponse(AbstractStruct):
    chat_id: int

    def __init__(self, chat_id: int):
        self.chat_id = chat_id

    @classmethod
    def load(cls, data: dict) -> "UpdateChatRsaKeyResponse":
        return cls(chat_id=data["chat_id"])

    def dump(self) -> dict:
        return {"chat_id": self.chat_id}


# UpdateChatRsaKeyNotification class
class UpdateChatRsaKeyNotification(AbstractStruct):
    chat_id: int
    user_id: int
    rsa_public_key: Base64Bytes

    def __init__(self, chat_id: int, user_id: int, rsa_public_key: some_bytes):
        self.chat_id = chat_id
        self.user_id = user_id
        self.rsa_public_key = Base64Bytes(rsa_public_key)

    @classmethod
    def load(cls, data: dict) -> "UpdateChatRsaKeyNotification":
        return cls(
            chat_id=data["chat_id"],
            user_id=data["user_id"],
            rsa_public_key=Base64Bytes.load(data["rsa_public_key"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "rsa_public_key": self.rsa_public_key.dump(),
        }


# SendMessageRequest class
class SendMessageRequest(AbstractStruct):
    chat_id: int
    encrypted_message: Base64Bytes
    message_ecdsa_signature: Base64Bytes

    def __init__(
        self,
        chat_id: int,
        encrypted_message: some_bytes,
        message_ecdsa_signature: some_bytes,
    ):
        self.chat_id = chat_id
        self.encrypted_message = Base64Bytes(encrypted_message)
        self.message_ecdsa_signature = Base64Bytes(message_ecdsa_signature)

    @classmethod
    def load(cls, data: dict) -> "SendMessageRequest":
        return cls(
            chat_id=data["chat_id"],
            encrypted_message=Base64Bytes.load(data["encrypted_message"]),
            message_ecdsa_signature=Base64Bytes.load(data["message_ecdsa_signature"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "encrypted_message": self.encrypted_message.dump(),
            "message_ecdsa_signature": self.message_ecdsa_signature.dump(),
        }


# SendMessageResponse class
class SendMessageResponse(AbstractStruct):
    chat_id: int
    message_id: int

    def __init__(self, chat_id: int, message_id: int):
        self.chat_id = chat_id
        self.message_id = message_id

    @classmethod
    def load(cls, data: dict) -> "SendMessageResponse":
        return cls(chat_id=data["chat_id"], message_id=data["message_id"])

    def dump(self) -> dict:
        return {"chat_id": self.chat_id, "message_id": self.message_id}


# SendMessageNotification class
class SendMessageNotification(AbstractStruct):
    chat_id: int
    message_id: int
    sender_user_id: int
    encrypted_message: Base64Bytes
    message_ecdsa_signature: Base64Bytes

    def __init__(
        self,
        chat_id: int,
        message_id: int,
        sender_user_id: int,
        encrypted_message: some_bytes,
        message_ecdsa_signature: some_bytes,
    ):
        self.chat_id = chat_id
        self.message_id = message_id
        self.sender_user_id = sender_user_id
        self.encrypted_message = Base64Bytes(encrypted_message)
        self.message_ecdsa_signature = Base64Bytes(message_ecdsa_signature)

    @classmethod
    def load(cls, data: dict) -> "SendMessageNotification":
        return cls(
            chat_id=data["chat_id"],
            message_id=data["message_id"],
            sender_user_id=data["sender_user_id"],
            encrypted_message=Base64Bytes.load(data["encrypted_message"]),
            message_ecdsa_signature=Base64Bytes.load(data["message_ecdsa_signature"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "message_id": self.message_id,
            "sender_user_id": self.sender_user_id,
            "encrypted_message": self.encrypted_message.dump(),
            "message_ecdsa_signature": self.message_ecdsa_signature.dump(),
        }


# SendFileRequest class
class SendFileRequest(AbstractStruct):
    chat_id: int
    encrypted_file: Base64Bytes
    encrypted_mime_type: Base64Bytes
    file_ecdsa_signature: Base64Bytes

    def __init__(
        self,
        chat_id: int,
        encrypted_file: some_bytes,
        encrypted_mime_type: some_bytes,
        file_ecdsa_signature: some_bytes,
    ):
        self.chat_id = chat_id
        self.encrypted_file = Base64Bytes(encrypted_file)
        self.encrypted_mime_type = Base64Bytes(encrypted_mime_type)
        self.file_ecdsa_signature = Base64Bytes(file_ecdsa_signature)

    @classmethod
    def load(cls, data: dict) -> "SendFileRequest":
        return cls(
            chat_id=data["chat_id"],
            encrypted_file=Base64Bytes.load(data["encrypted_file"]),
            encrypted_mime_type=Base64Bytes.load(data["encrypted_mime_type"]),
            file_ecdsa_signature=Base64Bytes.load(data["file_ecdsa_signature"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "encrypted_file": self.encrypted_file.dump(),
            "encrypted_mime_type": self.encrypted_mime_type.dump(),
            "file_ecdsa_signature": self.file_ecdsa_signature.dump(),
        }


# SendFileResponse class
class SendFileResponse(AbstractStruct):
    chat_id: int
    message_id: int

    def __init__(self, chat_id: int, message_id: int):
        self.chat_id = chat_id
        self.message_id = message_id

    @classmethod
    def load(cls, data: dict) -> "SendFileResponse":
        return cls(chat_id=data["chat_id"], message_id=data["message_id"])

    def dump(self) -> dict:
        return {"chat_id": self.chat_id, "message_id": self.message_id}


# SendFileNotification class
class SendFileNotification(AbstractStruct):
    chat_id: int
    message_id: int
    sender_user_id: int
    encrypted_file: Base64Bytes
    encrypted_mime_type: Base64Bytes
    file_ecdsa_signature: Base64Bytes

    def __init__(
        self,
        chat_id: int,
        message_id: int,
        sender_user_id: int,
        encrypted_file: some_bytes,
        encrypted_mime_type: some_bytes,
        file_ecdsa_signature: some_bytes,
    ):
        self.chat_id = chat_id
        self.message_id = message_id
        self.sender_user_id = sender_user_id
        self.encrypted_file = Base64Bytes(encrypted_file)
        self.encrypted_mime_type = Base64Bytes(encrypted_mime_type)
        self.file_ecdsa_signature = Base64Bytes(file_ecdsa_signature)

    @classmethod
    def load(cls, data: dict) -> "SendFileNotification":
        return cls(
            chat_id=data["chat_id"],
            message_id=data["message_id"],
            sender_user_id=data["sender_user_id"],
            encrypted_file=Base64Bytes.load(data["encrypted_file"]),
            encrypted_mime_type=Base64Bytes.load(data["encrypted_mime_type"]),
            file_ecdsa_signature=Base64Bytes.load(data["file_ecdsa_signature"]),
        )

    def dump(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "message_id": self.message_id,
            "sender_user_id": self.sender_user_id,
            "encrypted_file": self.encrypted_file.dump(),
            "encrypted_mime_type": self.encrypted_mime_type.dump(),
            "file_ecdsa_signature": self.file_ecdsa_signature.dump(),
        }


# IncomingNotification class
class IncomingNotification(AbstractStruct):
    notification: some_notification
    ecdsa_signature: Base64Bytes

    def __init__(self, notification: some_notification, ecdsa_signature: some_bytes):
        self.notification = notification  # This should be an instance of one of the Notification subclasses
        self.ecdsa_signature = Base64Bytes(ecdsa_signature)

    @classmethod
    def load(cls, data):
        notification_type = data["type"]
        notification = None

        if notification_type == NotificationType.INIT_CHAT_FROM_INITIALIZER.value:
            notification = InitChatFromInitializerNotification.load(
                data["notification"]
            )
        elif notification_type == NotificationType.INIT_CHAT_FROM_RECEIVER.value:
            notification = InitChatFromReceiverNotification.load(data["notification"])
        elif notification_type == NotificationType.UPDATE_CHAT_RSA_KEY.value:
            notification = UpdateChatRsaKeyNotification.load(data["notification"])
        elif notification_type == NotificationType.SEND_MESSAGE.value:
            notification = SendMessageNotification.load(data["notification"])
        elif notification_type == NotificationType.SEND_FILE.value:
            notification = SendFileNotification.load(data["notification"])
        else:
            raise ValueError(f"unknown notification type: {notification_type}")

        return cls(
            notification=notification,
            ecdsa_signature=Base64Bytes.load(data.get("ecdsa_signature", "")),
        )

    def dump(self):
        notification_type = None
        if isinstance(self.notification, InitChatFromInitializerNotification):
            notification_type = NotificationType.INIT_CHAT_FROM_INITIALIZER.value
        elif isinstance(self.notification, InitChatFromReceiverNotification):
            notification_type = NotificationType.INIT_CHAT_FROM_RECEIVER.value
        elif isinstance(self.notification, UpdateChatRsaKeyNotification):
            notification_type = NotificationType.UPDATE_CHAT_RSA_KEY.value
        elif isinstance(self.notification, SendMessageNotification):
            notification_type = NotificationType.SEND_MESSAGE.value
        elif isinstance(self.notification, SendFileNotification):
            notification_type = NotificationType.SEND_FILE.value
        else:
            raise ValueError(
                f"unknown notification type: {type(self.notification).__name__}"
            )

        return {
            "notification": self.notification.dump() if self.notification else None,
            "ecdsa_signature": self.ecdsa_signature.dump(),
            "type": notification_type,
        }


class GetNotificationsRequest(AbstractStruct):
    limit: int

    def __init__(self, limit: int):
        self.limit = limit

    @classmethod
    def load(cls, data: dict) -> "GetNotificationsRequest":
        return cls(limit=data["limit"])

    def dump(self) -> dict:
        return {"limit": self.limit}


# GetNotificationsResponse class
class GetNotificationsResponse(AbstractStruct):
    notifications: typing.List[IncomingNotification]

    def __init__(self, notifications: typing.List[IncomingNotification]):
        self.notifications = notifications

    @classmethod
    def load(cls, data: dict) -> "GetNotificationsResponse":
        notifications = [
            IncomingNotification.load(n) for n in data.get("notifications", [])
        ]
        return cls(notifications=notifications)

    def dump(self) -> dict:
        return {"notifications": [n.dump() for n in self.notifications]}
