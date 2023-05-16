import os
from typing import Optional, Union, Any
from pydantic import BaseModel, SecretStr, FilePath, HttpUrl
from datetime import datetime

class ClientConfig(BaseModel):
    server_url: HttpUrl
    realm_name: str
    client_id: str
    client_secret: SecretStr
    token_filename: Optional[FilePath] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    verify: Union[bool, str] = True

class TokenFileContent(BaseModel):
    server_url: HttpUrl
    realm_name: str
    token_timestamp: float
    access_token: str
    access_token_lifespan: int = -1
    refresh_token: Union[str, None]
    refresh_token_lifespan: int = -1