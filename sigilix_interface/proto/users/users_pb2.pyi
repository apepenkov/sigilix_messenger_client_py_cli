from typing import Any, bytes

class PublicUserInfo:
    user_id: int
    ecdsa_public_key: bytes
    username: str
    initial_rsa_public_key: bytes
    def __init__(
        self,
        user_id: int,
        ecdsa_public_key: bytes,
        username: str,
        initial_rsa_public_key: bytes,
    ):
        pass

class PrivateUserInfo:
    public_info: PublicUserInfo
    search_by_username_allowed: bool
    def __init__(self, public_info: PublicUserInfo, search_by_username_allowed: bool):
        pass

class LoginRequest:
    client_ecdsa_public_key: bytes
    client_rsa_public_key: bytes
    def __init__(self, client_ecdsa_public_key: bytes, client_rsa_public_key: bytes):
        pass

class LoginResponse:
    private_info: PrivateUserInfo
    user_id: int
    server_ecdsa_public_key: bytes
    def __init__(
        self,
        private_info: PrivateUserInfo,
        user_id: int,
        server_ecdsa_public_key: bytes,
    ):
        pass

class SetUsernameConfigRequest:
    username: str
    search_by_username_allowed: bool
    def __init__(self, username: str, search_by_username_allowed: bool):
        pass

class SetUsernameConfigResponse:
    success: bool
    def __init__(self, success: bool):
        pass

class SearchByUsernameRequest:
    username: str
    def __init__(self, username: str):
        pass

class SearchByUsernameResponse:
    public_info: PublicUserInfo
    def __init__(self, public_info: PublicUserInfo):
        pass

class UserServiceStub:
    def Login(self, request: LoginRequest, context: Any) -> LoginResponse: ...
    def SetUsernameConfig(
        self, request: SetUsernameConfigRequest, context: Any
    ) -> SetUsernameConfigResponse: ...
    def SearchByUsername(
        self, request: SearchByUsernameRequest, context: Any
    ) -> SearchByUsernameResponse: ...
