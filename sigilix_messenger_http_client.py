import argparse
import asyncio
import enum
import json
import logging
import os.path
import sys
import typing

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import aiohttp
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import CompleteStyle

from sigilix_interface import crypto_utils, http_api_classes

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

logger = logging.getLogger(__name__)
try:
    import mimetypes
except ImportError:
    logger.warning("mimetypes module is not available")
    mimetypes = None


# Enum to represent chat roles in the system.
class MyChatRole(enum.Enum):
    INITIALIZER = 1
    RECEIVER = 2


# Define the ChatInfo class that handles chat state and notifications.
class ChatInfo:
    """
    ChatInfo manages a chat session within the Sigilix Messenger Client, handling
    chat interactions such as initialization, message sending and receiving, encryption, and
    processing of incoming notifications related to the chat.

    Attributes:
        client (SigilixMessengerClient): The client instance to which this chat belongs.
        role (MyChatRole): The role of the user in this chat (initializer or receiver).
        chat_id (int): The unique identifier for this chat session.
        _pending_incoming_notifications (asyncio.Queue): Queue for storing and processing incoming notifications.
        _my_rsa_private_key (rsa.RSAPrivateKey, optional): The RSA private key of the client for this chat session.
        _other_rsa_public_key (rsa.RSAPublicKey, optional): The RSA public key of the other user in the chat session.
        _other_ecdsa_public_key (ec.EllipticCurvePublicKey, optional): The ECDSA public key of the other user in the chat session.
    """

    def __init__(
        self, chat_id: int, client: "SigilixMessengerClient", role: MyChatRole
    ):
        """
        Initializes a new instance of ChatInfo with the given chat ID, client, and role.

        Args:
            chat_id (int): The unique identifier for the chat session.
            client (SigilixMessengerClient): The client instance to which this chat belongs.
            role (MyChatRole): The role of the user in this chat (initializer or receiver).
        """
        self.client: SigilixMessengerClient = client
        self.role: MyChatRole = role
        self.chat_id: int = chat_id
        self._pending_incoming_notifications = asyncio.Queue()
        self._my_rsa_private_key: typing.Optional[rsa.RSAPrivateKey] = client.rsa_key
        self._other_rsa_public_key: typing.Optional[rsa.RSAPublicKey] = None
        self._other_ecdsa_public_key: typing.Optional[ec.EllipticCurvePublicKey] = None
        asyncio.create_task(self.processor_notifs())

    @classmethod
    def init_from_notification(
        cls,
        chat_id: int,
        client: "SigilixMessengerClient",
        notification: http_api_classes.IncomingNotification,
        role: MyChatRole,
    ):
        """
        Initializes a ChatInfo instance from an incoming notification.

        Args:
            chat_id (int): The unique identifier for the chat session.
            client (SigilixMessengerClient): The client instance to which this chat belongs.
            notification (http_api_classes.IncomingNotification): The incoming notification that triggered the chat initialization.
            role (MyChatRole): The role of the user in this chat (initializer or receiver).

        Returns:
            ChatInfo: An initialized chat session object.

        Raises:
            ValueError: If the notification is not a recognized chat initialization notification.
        """
        if not isinstance(
            notification.notification,
            (
                http_api_classes.InitChatFromReceiverNotification,
                http_api_classes.InitChatFromInitializerNotification,
            ),
        ):
            raise ValueError("Invalid notification")

        chat_info = cls(chat_id, client, role)
        chat_info.put_notification(notification)
        return chat_info

    def put_notification(self, notification: http_api_classes.IncomingNotification):
        """
        Adds an incoming notification to the processing queue.

        Args:
            notification (http_api_classes.IncomingNotification): The incoming notification to be added to the queue.
        """
        self._pending_incoming_notifications.put_nowait(notification)

    def set_private_key(self, key: bytes):
        """
        Sets the RSA private key for the client in the current chat session.

        Args:
            key (bytes): The RSA private key in PEM format as a byte string.
        """
        self._my_rsa_private_key = crypto_utils.rsa_private_key_from_bytes_pem(key)

    def set_other_rsa_public_key(self, key: bytes):
        """
        Sets the RSA public key of the other user in the chat session.

        Args:
            key (bytes): The RSA public key in PEM format as a byte string.
        """
        self._other_rsa_public_key = crypto_utils.rsa_public_key_from_bytes_der(key)

    def set_other_ecdsa_public_key(self, key: bytes):
        """
        Sets the ECDSA public key of the other user in the chat session.

        Args:
            key (bytes): The ECDSA public key as a byte string.
        """
        self._other_ecdsa_public_key = crypto_utils.ecdsa_public_key_from_bytes(key)

    @property
    def ready_for_communication(self):
        """
        Checks if the chat session is ready for communication by ensuring that all necessary keys are set.

        Returns:
            bool: True if the chat is ready for communication, False otherwise.
        """
        return (
            self._my_rsa_private_key is not None
            and self._other_rsa_public_key is not None
            and self._other_ecdsa_public_key is not None
        )

    async def rekey(self):
        """
        Generates a new RSA key pair for the client and updates the chat session with the new public key.

        Raises:
            Any exceptions raised by the underlying client.update_chat_rsa_key method.
        """
        new_key = crypto_utils.generate_rsa_key()

        await self.client.update_chat_rsa_key(
            self.chat_id,
            crypto_utils.rsa_public_key_to_bytes_der(new_key.public_key()),
        )
        self.set_private_key(crypto_utils.rsa_private_key_to_bytes_pem(new_key))

    def log(self, *args, **kwargs):
        arg_one = args[0]
        args = args[1:]
        logger.info(f"Chat [{self.chat_id}]: {arg_one}", *args, **kwargs)

    def log_with_level(self, level, *args, **kwargs):
        arg_one = args[0]
        args = args[1:]
        logger.log(level, f"Chat [{self.chat_id}]: {arg_one}", *args, **kwargs)

    async def processor_notifs(self):
        """
        Asynchronously processes incoming notifications from the queue and takes appropriate actions based on the notification type.

        Raises:
            ValueError: If an invalid chat ID is encountered or an invalid notification type is received.
        """
        while True:
            res: http_api_classes.IncomingNotification = (
                await self._pending_incoming_notifications.get()
            )
            notif = res.notification
            if not isinstance(
                notif,
                (
                    http_api_classes.InitChatFromInitializerNotification,
                    http_api_classes.InitChatFromReceiverNotification,
                ),
            ):
                chat_id = getattr(notif, "chat_id", None)
                if chat_id and chat_id != self.chat_id:
                    raise ValueError("Invalid chat id!")

            if isinstance(notif, http_api_classes.InitChatFromInitializerNotification):
                # receives from server, when user X wants to start dialog with user Y (self)
                if self.role != MyChatRole.RECEIVER:
                    raise ValueError("Invalid role")
                self.chat_id = notif.chat_id
                self.set_other_rsa_public_key(
                    bytes(notif.initializer_user_info.initial_rsa_public_key)
                )
                self.set_other_ecdsa_public_key(
                    bytes(notif.initializer_user_info.ecdsa_public_key)
                )
                self.log(
                    "Chat initialization was requested by user %d",
                    notif.initializer_user_info.user_id,
                )
            elif isinstance(notif, http_api_classes.InitChatFromReceiverNotification):
                if self.role != MyChatRole.INITIALIZER:
                    raise ValueError("Invalid role")
                self.set_other_rsa_public_key(
                    bytes(notif.receiver_user_info.initial_rsa_public_key)
                )
                self.set_other_ecdsa_public_key(
                    bytes(notif.receiver_user_info.ecdsa_public_key)
                )
                self.log("Chat initialization was accepted")
            elif isinstance(notif, http_api_classes.UpdateChatRsaKeyNotification):
                self.set_other_rsa_public_key(bytes(notif.rsa_public_key))
                self.log("Chat RSA key was updated")
            elif isinstance(notif, http_api_classes.SendMessageNotification):
                decrypted_message = self._decrypt_message(
                    bytes(notif.encrypted_message), bytes(notif.message_ecdsa_signature)
                )
                self.log(f"Received a message: {decrypted_message}")
            elif isinstance(notif, http_api_classes.SendFileNotification):
                decrypted_mime_type, decrypted_data = self._decrypt_file(
                    bytes(notif.encrypted_file),
                    bytes(notif.encrypted_mime_type),
                    bytes(notif.file_ecdsa_signature),
                )

                if mimetypes is not None:
                    fileext = mimetypes.guess_extension(decrypted_mime_type)
                else:
                    fileext = ".bin"
                path = f"received_file{fileext}"
                with open(f"received_file{fileext}", "wb") as f:
                    f.write(decrypted_data)
                self.log(f"File saved to {path}")
            else:
                raise ValueError("Invalid notification")

    async def accept(self):
        """
        Accepts a chat invitation based on the role of the client in the chat session.

        Raises:
            ValueError: If the client role is not suitable for accepting the chat (e.g., the client is not the receiver).
        """
        if self.role != MyChatRole.RECEIVER:
            raise ValueError("Invalid role")
        await self.client.init_chat_from_receiver(self.chat_id)

    async def send_message(self, message: str):
        """
        Sends an encrypted message to the other user in the chat session.

        Args:
            message (str): The message to be sent.

        Raises:
            ValueError: If the chat session is not ready for communication.
        """
        if not self.ready_for_communication:
            raise ValueError("Not ready for communication")
        data = message.encode("utf-8")
        encrypted_message = crypto_utils.rsa_encrypt(self._other_rsa_public_key, data)
        signature = crypto_utils.sign_message(self.client.ecdsa_key, data)
        await self.client.send_message(self.chat_id, encrypted_message, signature)

    def _decrypt_message(self, encrypted_message: bytes, signature: bytes) -> str:
        """
        Decrypts an encrypted message received in the chat session.

        Args:
            encrypted_message (bytes): The encrypted message to be decrypted.
            signature (bytes): The ECDSA signature of the message.

        Returns:
            str: The decrypted message.

        Raises:
            ValueError: If the message is invalid or the signature does not match.
        """
        decrypted_message = crypto_utils.rsa_decrypt(
            self._my_rsa_private_key, encrypted_message
        )
        if not decrypted_message:
            raise ValueError("Invalid message")
        if not crypto_utils.validate_signature(
            self._other_ecdsa_public_key,
            decrypted_message,
            signature,
        ):
            raise ValueError("Invalid signature")
        return decrypted_message.decode("utf-8")

    async def send_file(self, file_path: str):
        """
        Sends an encrypted file to the other user in the chat session.

        Args:
            file_path (str): The path to the file to be sent.

        Raises:
            ValueError: If the chat session is not ready for communication or the file cannot be read.
        """
        if not self.ready_for_communication:
            raise ValueError("Not ready for communication")
        with open(file_path, "rb") as f:
            data = f.read()

        if mimetypes is not None:
            mime_type = mimetypes.guess_type(file_path)[0]
        else:
            mime_type = "application/octet-stream"

        encrypted_mime_type = crypto_utils.rsa_encrypt(
            self._other_rsa_public_key, mime_type.encode("utf-8")
        )
        encrypted_data = crypto_utils.rsa_encrypt(self._other_rsa_public_key, data)
        signature = crypto_utils.sign_message(self.client.ecdsa_key, data)
        await self.client.send_file(
            self.chat_id, encrypted_data, encrypted_mime_type, signature
        )

    async def _decrypt_file(
        self,
        encrypted_file: bytes,
        encrypted_mime_type: bytes,
        file_ecdsa_signature: bytes,
    ) -> typing.Tuple[str, bytes]:
        """
        Decrypts an encrypted file received in the chat session.

        Args:
            encrypted_file (bytes): The encrypted file data to be decrypted.
            encrypted_mime_type (bytes): The encrypted MIME type of the file.
            file_ecdsa_signature (bytes): The ECDSA signature of the file.

        Returns:
            tuple: A tuple containing the decrypted MIME type and file data.

        Raises:
            ValueError: If the file data or MIME type is invalid, or the signature does not match.
        """
        decrypted_data = crypto_utils.rsa_decrypt(
            self._my_rsa_private_key, encrypted_file
        )
        if not decrypted_data:
            raise ValueError("Invalid file")
        if not crypto_utils.validate_signature(
            self._other_ecdsa_public_key,
            decrypted_data,
            file_ecdsa_signature,
        ):
            raise ValueError("Invalid signature")
        decrypted_mime_type = crypto_utils.rsa_decrypt(
            self._my_rsa_private_key, encrypted_mime_type
        )
        if not decrypted_mime_type:
            raise ValueError("Invalid mime type")
        return decrypted_mime_type.decode("utf-8"), decrypted_data


class ErrorCode(enum.Enum):
    """
        type ErrorCodes int

    const (
            ErrCodeUnknown ErrorCodes = iota
            ErrInternal
            ErrUnauthenticated
            ErrPermissionDenied
            AlreadyExists
            ErrNotFound
    )
    """

    UNKNOWN = 0
    INTERNAL = 1
    UNAUTHENTICATED = 2
    PERMISSION_DENIED = 3
    ALREADY_EXISTS = 4
    NOT_FOUND = 5


class SigilixServerException(Exception):
    def __init__(self, resp_json: dict):
        self.code = ErrorCode(resp_json["code"])
        self.message = resp_json["message"]

    def __str__(self):
        return f"Error code {self.code}: {self.message}"

    def __repr__(self):
        return f"SigilixServerException({self.code}, {self.message})"


# Define the main SigilixMessengerClient class for the client application.
class SigilixMessengerClient:
    """
    The SigilixMessengerClient class is responsible for handling the client-side operations
    of the Sigilix messaging service. It manages user authentication, sending and receiving
    messages, initiating and managing chat sessions, and user settings like username and search
    preferences.

    Attributes:
        ecdsa_key (EllipticCurvePrivateKey): The ECDSA private key for cryptographic operations.
        rsa_key (RSAPrivateKey): The RSA private key for cryptographic operations.
        addr (str): The server address for the messaging service.
        server_cert (Optional[bytes]): The server's certificate for establishing a TLS connection.
        use_tls (bool): Flag to enable or disable TLS for the connection.
        user_id (int): The unique identifier for the user, derived from the ECDSA public key.
        _logged_in_success (bool): Flag to indicate whether the user has logged in successfully.
        _chats (Dict[int, ChatInfo]): A dictionary of chat sessions indexed by chat IDs.
        _username (Optional[str]): The username of the client.
        _allow_search_by_username (bool): Flag to allow searching for this user by username.
    """

    def __init__(
        self,
        ecdsa_key: ec.EllipticCurvePrivateKey,
        rsa_key: rsa.RSAPrivateKey,
        addr: str,
        use_tls: bool = True,
        username: typing.Optional[str] = None,
        allow_search_by_username: bool = False,
    ):
        """
        Initialize the SigilixMessengerClient with the required cryptographic keys, server
        information, and optional user configurations.

        Args:
            ecdsa_key (EllipticCurvePrivateKey): The private ECDSA key for signing operations.
            rsa_key (RSAPrivateKey): The private RSA key for encryption/decryption operations.
            addr (str): The server address to connect to for the messaging service.
            use_tls (bool, optional): Whether to use TLS for the connection. Defaults to True.
            username (Optional[str], optional): The desired username for the client. Defaults to None.
            allow_search_by_username (bool, optional): Whether the client can be searched by username. Defaults to False.
        """
        self.ecdsa_key = ecdsa_key
        self.rsa_key = rsa_key
        self._pub_ecdsa_bytes = crypto_utils.ecdsa_public_key_to_bytes(
            self.ecdsa_key.public_key()
        )
        self.addr = addr
        self.base_url = f"https://{addr}/api/" if use_tls else f"http://{addr}/api/"
        self.use_tls = use_tls
        self.user_id = crypto_utils.generate_user_id_by_public_key(
            self.ecdsa_key.public_key()
        )
        logger.info("Sigilix Messenger Client initialized")
        logger.info(
            "Client ECDSA public key: %s",
            crypto_utils.bytes_to_base64(
                crypto_utils.ecdsa_public_key_to_bytes(self.ecdsa_key.public_key())
            ),
        )
        self._logged_in_success = False
        self._chats: typing.Dict[int, ChatInfo] = {}
        self._username = username
        self._allow_search_by_username = allow_search_by_username

    async def _make_request(
        self,
        request: http_api_classes.AbstractStruct,
        path: str,
        expected_response_type: typing.Type[http_api_classes.AbstractStruct],
    ):
        """
        Make an HTTP request to the server.

        Args:
            request (Base): The request object to send to the server.
            path (str): The path to send the request to.
            expected_response_type (Type[Base]): The expected type of the response.

        Raises:
            ValueError: If the response type does not match the expected type.
        """
        async with aiohttp.ClientSession() as session:
            full_path = f"{self.base_url}{path}"
            data = json.dumps(request.dump(), separators=(",", ":")).encode("utf-8")
            signature = self.sign(data)
            # logger.info(f"Sending request to {full_path}: {request.dump()}, signature: {signature}")
            async with session.post(
                full_path,
                data=data,
                headers={
                    "X-Sigilix-User-Id": str(self.user_id),
                    "X-Sigilix-Signature": signature,
                    "Content-Type": "application/json",
                },
            ) as resp:
                if resp.status >= 400:
                    try:
                        resp_json = await resp.json()
                        raise SigilixServerException(resp_json)
                    except Exception:
                        pass
                    raise ValueError(f"HTTP error: {resp.status}")
                data = await resp.json()
                return expected_response_type.load(data)

    def sign(self, data: bytes) -> str:
        """
        Sign the provided data using the client's ECDSA private key.

        Args:
            data (bytes): The data to sign.

        Returns:
            str: The base64-encoded signature.
        """
        return crypto_utils.bytes_to_base64(
            crypto_utils.sign_message(
                self.ecdsa_key,
                data,
            )
        )

    # def validate_signature(self, data: bytes, signature: str) -> bool:
    #     """
    #     Validate a signature against the provided data using the server's ECDSA public key.
    #
    #     Args:
    #         data (bytes): The data that was signed.
    #         signature (str): The base64-encoded signature to verify.
    #
    #     Returns:
    #         bool: True if the signature is valid, False otherwise.
    #     """
    #     return crypto_utils.validate_signature(
    #         self.host_ecdsa_public_key,
    #         data,
    #         crypto_utils.base64_to_bytes(signature),
    #     )

    async def main_loop(self, signal_on_login: typing.Optional[asyncio.Event] = None):
        """
        The main loop for the client, handling login and continuous polling for notifications.

        Args:
            signal_on_login (Optional[asyncio.Event], optional): An asyncio Event to signal when the login is successful.

        Raises:
            Any exceptions that occur during the login process or notification polling.
        """

        request = http_api_classes.LoginRequest(
            client_ecdsa_public_key=self._pub_ecdsa_bytes,
            client_rsa_public_key=crypto_utils.rsa_public_key_to_bytes_der(
                self.rsa_key.public_key()
            ),
        )
        await self._make_request(request, "users/login", http_api_classes.LoginResponse)

        self._logged_in_success = True
        if signal_on_login is not None:
            signal_on_login.set()
        logger.info("Logged in successfully")
        if self._username:
            await self.set_username(self._username, self._allow_search_by_username)
        while True:
            for notif in (await self.get_notifications()).notifications:
                self._propagate_notification(notif)
            await asyncio.sleep(1)

    def _propagate_notification(
        self, incoming_notif: http_api_classes.IncomingNotification
    ):
        """
        Handle an incoming notification by either initializing a new chat session or passing
        it to the appropriate existing chat session.

        Args:
            incoming_notif (IncomingNotification): The incoming notification to handle.

        Raises:
            ValueError: If the notification is not associated with a known chat ID.
        """
        notification = incoming_notif.notification

        chat_id = getattr(notification, "chat_id", None)
        if chat_id:
            if chat_id not in self._chats:
                if isinstance(
                    notification,
                    (
                        http_api_classes.InitChatFromInitializerNotification,
                        http_api_classes.InitChatFromReceiverNotification,
                    ),
                ):
                    if isinstance(
                        notification,
                        http_api_classes.InitChatFromInitializerNotification,
                    ):
                        role = MyChatRole.RECEIVER
                    else:
                        role = MyChatRole.INITIALIZER

                    self._chats[chat_id] = ChatInfo.init_from_notification(
                        chat_id, self, incoming_notif, role
                    )
                else:
                    logger.warning(
                        f"Received non-init notification for unknown chat id: {chat_id}"
                    )
            else:
                self._chats[chat_id].put_notification(incoming_notif)
        else:
            logger.error("Received notification without chat id")


    async def set_username(self, username: str, search_by_username_allowed: bool):
        return await self._make_request(
            http_api_classes.SetUsernameConfigRequest(
                username=username,
                search_by_username_allowed=search_by_username_allowed,
            ),
            "users/set_username_config",
            http_api_classes.SetUsernameConfigResponse,
        )

    async def search_by_username(
        self, username: str
    ) -> typing.Optional[http_api_classes.SearchByUsernameResponse]:
        # )
        res = await self._make_request(
            http_api_classes.SearchByUsernameRequest(
                username=username,
            ),
            "users/search_by_username",
            http_api_classes.SearchByUsernameResponse,
        )
        if res.public_info.user_id:
            return res
        return None

    async def init_chat_from_initializer(
        self,
        target_user_id: int,
    ) -> http_api_classes.InitChatFromInitializerResponse:
        return await self._make_request(
            http_api_classes.InitChatFromInitializerRequest(
                target_user_id=target_user_id,
            ),
            "messages/init_chat_from_initializer",
            http_api_classes.InitChatFromInitializerResponse,
        )

    async def init_chat_from_receiver(
        self,
        chat_id: int,
    ) -> http_api_classes.InitChatFromReceiverResponse:
        return await self._make_request(
            http_api_classes.InitChatFromReceiverRequest(
                chat_id=chat_id,
            ),
            "messages/init_chat_from_receiver",
            http_api_classes.InitChatFromReceiverResponse,
        )

    async def update_chat_rsa_key(
        self,
        chat_id: int,
        rsa_public_key: bytes,
    ) -> http_api_classes.UpdateChatRsaKeyResponse:
        return await self._make_request(
            http_api_classes.UpdateChatRsaKeyRequest(
                chat_id=chat_id,
                rsa_public_key=rsa_public_key,
            ),
            "messages/update_chat_rsa_key",
            http_api_classes.UpdateChatRsaKeyResponse,
        )

    async def send_message(
        self,
        chat_id: int,
        encrypted_message: bytes,
        message_ecdsa_signature: bytes,
    ) -> http_api_classes.SendMessageResponse:
        return await self._make_request(
            http_api_classes.SendMessageRequest(
                chat_id=chat_id,
                encrypted_message=encrypted_message,
                message_ecdsa_signature=message_ecdsa_signature,
            ),
            "messages/send_message",
            http_api_classes.SendMessageResponse,
        )

    async def send_file(
        self,
        chat_id: int,
        encrypted_file: bytes,
        encrypted_mime_type: bytes,
        file_ecdsa_signature: bytes,
    ) -> http_api_classes.SendFileResponse:
        return await self._make_request(
            http_api_classes.SendFileRequest(
                chat_id=chat_id,
                encrypted_file=encrypted_file,
                encrypted_mime_type=encrypted_mime_type,
                file_ecdsa_signature=file_ecdsa_signature,
            ),
            "messages/send_file",
            http_api_classes.SendFileResponse,
        )

    async def get_notifications(
        self, limit: int = 10
    ) -> http_api_classes.GetNotificationsResponse:
        return await self._make_request(
            http_api_classes.GetNotificationsRequest(
                limit=limit,
            ),
            "messages/get_notifications",
            http_api_classes.GetNotificationsResponse,
        )

    def chat(self, chat_id: int) -> ChatInfo:
        """
        Get a ChatInfo instance for the given chat ID.

        Args:
            chat_id (int): The unique identifier for the chat session.

        Returns:
            ChatInfo: The ChatInfo instance for the given chat ID.
        """
        if chat_id not in self._chats:
            raise ValueError("Unknown chat id")
        return self._chats[chat_id]

    async def request_chat(self, user_id: int) -> ChatInfo:
        """
        Request a chat session with the given user ID.

        Args:
            user_id (int): The unique identifier for the user with which to start a chat session.

        Returns:
            ChatInfo: The ChatInfo instance for the new chat session.
        """
        res = await self.init_chat_from_initializer(user_id)
        self._chats[res.chat_id] = ChatInfo(res.chat_id, self, MyChatRole.INITIALIZER)
        return self._chats[res.chat_id]


# Define an async CLI class to provide a command-line interface for the client.
class AsyncCLI:
    # This class provides an asynchronous CLI for interacting with the Sigilix client.
    def __init__(self, client: SigilixMessengerClient):
        self.commands = {
            "exit": self.exit,
            "send": self.send_message,
            "accept": self.accept,
            "search": self.search,
            "request_chat": self.request_chat,
            "help": self.help,
        }
        self.session = PromptSession()
        self.exit_requested = False
        self.client = client

    async def prepare_and_run(self):
        event = asyncio.Event()
        logger.info("Authenticating...")
        asyncio.create_task(self.client.main_loop(event))
        await event.wait()
        logger.info("Authenticated! Welcome to Sigilix Messenger!")
        await self.run()

    async def run(self):
        """Run the CLI session."""
        while not self.exit_requested:
            user_input = await self.session.prompt_async(
                ">>> ",
                completer=WordCompleter(list(self.commands.keys()), ignore_case=True),
                complete_style=CompleteStyle.COLUMN,
            )
            if not user_input:
                continue
            cmd, *args = user_input.split()
            cmd = cmd.lower()
            if cmd in self.commands:
                logger.info(f"Executing command: {cmd} with args: {args}")
                try:
                    await self.commands[cmd](*args)
                except Exception as e:
                    logger.exception(e)
            else:
                print(f"Unknown command: {cmd}")

    async def exit(self, *args):
        """Exit the CLI."""
        self.exit_requested = True
        exit(0)

    async def send_message(self, chat_id, *message):
        """Send a message to a chat."""
        # Assuming self.client is your client instance with chat method
        message = " ".join(message)
        try:
            chat = self.client.chat(int(chat_id))
        except ValueError:
            print("Invalid chat id")
            return
        await chat.send_message(message)
        print("Message sent")

    async def accept(self, chat_id):
        """Accept a chat invitation."""
        try:
            chat = self.client.chat(int(chat_id))
        except ValueError:
            print("Invalid chat id")
            return
        await chat.accept()
        print("Chat accepted")

    async def search(self, username):
        """Search a user by username."""
        res = await self.client.search_by_username(username)
        if not res.public_info.ecdsa_public_key:
            print("User not found")
        else:
            print(f"User found: {res.public_info.user_id}")

    async def request_chat(self, user_id):
        """Request a chat with a user."""
        chat = await self.client.request_chat(int(user_id))
        print(f"Chat created: {chat.chat_id}")

    async def help(self, *args):
        """Print help."""
        print(
            """Available commands:
- exit: exit the CLI
- send <chat_id> <message>: send a message to a chat
- accept <chat_id>: accept a chat invitation
- search <username>: search a user by username
- request_chat <user_id>: request a chat with a user
- help: print this help
"""
        )


async def main():
    if sys.argv[-1] == "generatekeys":
        ecdsa_key = crypto_utils.generate_ecdsa_private_key()
        rsa_key = crypto_utils.generate_rsa_key()
        print("DO NOT share your private keys with anyone!")
        print("ECDSA private key:")
        print(
            crypto_utils.bytes_to_base64(
                crypto_utils.ecdsa_private_key_to_bytes(ecdsa_key)
            )
        )
        print("RSA private key:")
        print(
            crypto_utils.rsa_private_key_to_bytes_pem(rsa_key).decode("utf-8"),
        )
        return

    parser = argparse.ArgumentParser(description="Sigilix Messenger Client")
    parser.add_argument(
        "-ek",
        "--ecdsa-key",
        type=str,
        required=True,
        help="ECDSA private key in base64",
    )
    parser.add_argument(
        "-rk",
        "--rsa-key",
        type=str,
        required=True,
        help="RSA private key in PEM format, or path to file with RSA private key in PEM format",
    )
    parser.add_argument(
        "-a",
        "--addr",
        type=str,
        required=True,
        help="Host address to connect to",
    )
    parser.add_argument(
        "-u",
        "--username",
        type=str,
        required=False,
        help="Username",
    )
    parser.add_argument(
        "-n",
        "--notls",
        action="store_true",
        required=False,
        help="Disable TLS",
    )
    args = parser.parse_args()

    if args.notls:
        logger.warning("TLS is disabled")

    if os.path.isfile(args.ecdsa_key):
        with open(args.ecdsa_key, "r") as f:
            args.ecdsa_key = f.read()

    if os.path.isfile(args.rsa_key):
        with open(args.rsa_key, "r") as f:
            args.rsa_key = f.read()

    client = SigilixMessengerClient(
        ecdsa_key=crypto_utils.ecdsa_private_key_from_bytes(
            crypto_utils.base64_to_bytes(args.ecdsa_key)
        ),
        rsa_key=crypto_utils.rsa_private_key_from_bytes_pem(args.rsa_key.encode()),
        addr=args.addr,
        username=args.username,
        allow_search_by_username=args.username is not None,
        use_tls=not args.notls,
    )
    cli = None
    try:
        cli = AsyncCLI(client)
    except Exception:
        logger.warning("Failed to initialize CLI")
        cli = None
    if cli:
        await cli.prepare_and_run()
    else:
        await client.main_loop()


if __name__ == "__main__":
    asyncio.run(main())
