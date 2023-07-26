from typing import Optional, Union
from pydantic import BaseModel, SecretStr, HttpUrl

class ClientConfig(BaseModel):
    server_url: HttpUrl
    realm_name: str
    client_id: str
    client_secret: SecretStr
    token_filename: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    verify: Union[bool, str] = True

class TokenFileContent(BaseModel):
    server_url: HttpUrl
    realm_name: str
    token_timestamp: float
    access_token: str
    access_token_lifespan: int = -1
    refresh_token: Union[str, None] = None
    refresh_token_lifespan: int = -1

    def to_json(self) -> dict:
        return {
            'server_url': self.server_url,
            'realm_name': self.realm_name,
            'token_timestamp': self.token_timestamp,
            'access_token': self.access_token,
            'access_token_lifespan': self.access_token_lifespan,
            'refresh_token': self.refresh_token,
            'refresh_token_lifespan': self.refresh_token_lifespan
        }