import os
from typing import Optional, Union, Any
from pydantic import SecretStr, validate_arguments, parse_obj_as
from filelock import FileLock
from keycloak.realm import KeycloakRealm
from keycloak.openid_connect import KeycloakOpenidConnect
import json
import time
import warnings
from pathlib import Path

from .models import ClientConfig, TokenFileContent

class SharedTokenClient(object):
    _realm: KeycloakRealm
    _client: KeycloakOpenidConnect
    __default_token_filename = './.pykeycloak/{}.tok'
    __token_filename: Union[Path, None] = None
    __lock_filename: Path

    @validate_arguments
    def __init__(
        self, 
        config: ClientConfig
    ):
        '''
            config: A map with the following keys
              'server_url': keycloak base server URL
              'realm_name': keycloak realm
              'client_id': client used for the original token
              'client_secret': secret needed to connect to Keycloak as the client
              'token_filename': path to file where the token are/will be stored in (optional)
              'access_token': initial access_token (optional)
              'refresh_token': initial refresh_token (optional)
              'verify': either 'true|false' or the path to the ca cert. Defaults to True
            username: username of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
            password: password of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
        '''
        self.config = config
        # Connect to Keycloak
        self._realm: KeycloakRealm = KeycloakRealm(self.config.server_url, self.config.realm_name)
        self._realm.client.session.verify = self.config.verify
        self._client: KeycloakOpenidConnect = self._realm.open_id_connect(
            self.config.client_id,
            self.config.client_secret.get_secret_value()
        )
        # Prep the files
        if config.token_filename is not None:
            self.__token_filename = Path(config.token_filename)
            self.__token_filename = self.__token_filename.resolve()
            if not self.__token_filename.parent.exists():
                os.makedirs(str(self.__token_filename.parent), exist_ok=True)
            self.__token_filename = config.token_filename
        else:
            os.makedirs('./.pykeycloak', exist_ok=True)
            self.__token_filename = Path(self.__default_token_filename.format(self.config.realm_name))
            self.__token_filename = self.__token_filename.resolve()
        self.__lock_filename = self.__token_filename.with_suffix('.lock')
        self.__lock = FileLock(self.__lock_filename)

    @validate_arguments
    async def initialize_tokens(
        self,
        username: Optional[str] = None, 
        password: Optional[SecretStr] = None
    ) -> TokenFileContent:
        # Initialize the tokens
        with self.__lock:
            try:
                if self.__token_filename.exists():
                    with open(self.__token_filename, 'r') as token_file:
                        token_file_contents = parse_obj_as(TokenFileContent, json.load(token_file))
                    # Check if the token is still valid
                    now = time.time()
                    if token_file_contents.access_token_lifespan < 0:
                        warnings.warn('We do not know if the access token has expired or not.')
                    elif now > token_file_contents.token_timestamp + token_file_contents.access_token_lifespan:
                        token_file_contents = await self.refresh_tokens(
                            token_file_contents = token_file_contents
                        ) # Refresh the token since it has expired
                    return token_file_contents
                elif self.config.access_token is not None and self.config.refresh_token is not None:
                    # Eagerly refresh the tokens so we know the expiry
                    token_file_contents = await self.refresh_tokens(
                        token_file_contents = TokenFileContent(
                            server_url=self.config.server_url,
                            realm_name=self.config.realm_name,
                            token_timestamp=time.time(),
                            access_token=self.config.access_token,
                            refresh_token=self.config.refresh_token
                        )
                    )
                    return token_file_contents
                elif username and password:
                    token_file_contents = await self.password_credentials(username, password)
                    return token_file_contents
                else:
                    raise FileNotFoundError('No token file exists')
            except Exception:
                if username and password:
                    token_file_contents = await self.password_credentials(username, password)
                    return token_file_contents
                else:
                    raise ValueError('Initial Tokens in config dict or username and password arguments must be provided if the token file does not exists.')
            
    def __parse_response(self, response: dict) -> TokenFileContent:
        with self.__lock:
            if not ('access_token' in response):
                raise KeyError('Response does not contain an access token')
            token_timestamp = time.time()
            access_token = response['access_token']
            if 'refresh_token' in response:
                refresh_token = response['refresh_token']
            else:
                refresh_token = None
            if 'expires_in' in response:
                access_token_lifespan = int(response['expires_in'])
            else:
                access_token_lifespan = -1 # Value to specify we do not know expiry
            if 'refresh_expires_in' in response:
                refresh_token_lifespan = int(response['refresh_expires_in'])
            else:
                refresh_token_lifespan = -1 # Value to specify we do not know expiry
            token_file_contents = TokenFileContent(
                server_url=self.config.server_url,
                realm_name=self.config.realm_name,
                token_timestamp=token_timestamp,
                access_token=access_token,
                refresh_token=refresh_token,
                access_token_lifespan=access_token_lifespan,
                refresh_token_lifespan=refresh_token_lifespan
            )
            with open(self.__token_filename, 'w') as token_file:
                json.dump(token_file_contents.to_json(), token_file)
            return token_file_contents.copy()
    
    async def __get_token_attributes(self) -> TokenFileContent:
        if self.__token_filename.exists():
            with self.__lock:
                with open(self.__token_filename, 'r') as token_file:
                    token_file_contents = parse_obj_as(TokenFileContent, json.load(token_file))
                return token_file_contents
        else:
            raise FileNotFoundError(f'No existing token found at {self.__token_filename}!')

    async def get_token_timestamp(self) -> float:
        '''
            Return the timestamp when the tokens where received from the auth server.
            None if unknown
        '''
        token_file_contents = await self.__get_token_attributes()
        return token_file_contents.token_timestamp

    async def get_access_token_expiry_timestamp(self) -> Union[float, None]:
        '''
            Return the timestamp when the access token expires
            None if unknown
        '''
        token_file_contents = await self.__get_token_attributes()
        if token_file_contents.access_token_lifespan < 0:
            return None
        return token_file_contents.token_timestamp + token_file_contents.access_token_lifespan

    async def get_refresh_token_expiry_timestamp(self) -> Union[float, None]:
        '''
            Return the timestamp when the refresh token expires
            None if unknown
        '''
        token_file_contents = await self.__get_token_attributes()
        if token_file_contents.refresh_token_lifespan < 0:
            return None
        return token_file_contents.token_timestamp + token_file_contents.refresh_token_lifespan
    
    async def get_access_token(self) -> str:
        with self.__lock:
            token_file_contents = await self.__get_token_attributes()
            now = time.time()
            access_token_expiry = token_file_contents.token_timestamp + token_file_contents.access_token_lifespan
            if token_file_contents.access_token_lifespan < 0:
                warnings.warn('We do not know if the access token has expired or not. We assume it has not.')
            elif now > access_token_expiry:
                new_token_file_contents = await self.refresh_tokens(
                    token_file_contents = token_file_contents
                ) # Refresh the token since it has expired
                return new_token_file_contents.access_token
            return token_file_contents.access_token

    async def get_refresh_token(self) -> Union[str, None]:
        with self.__lock:
            token_file_contents = await self.__get_token_attributes()
            if token_file_contents.refresh_token is None:
                return None
            now = time.time()
            refresh_token_expiry = token_file_contents.token_timestamp + token_file_contents.refresh_token_lifespan
            if token_file_contents.refresh_token_lifespan < 0:
                warnings.warn('We do not know if the refresh token has expired or not. We assume it has not.')
            elif now > refresh_token_expiry:
                # Refresh token has expired
                warnings.warn('Refresh token has expired. Use password_credentials(username: str, password: str) to get new tokens')
                return None
            return token_file_contents.refresh_token

    async def get_user_info(self) -> Any:
        with self.__lock:
            return self._client.userinfo(await self.get_access_token())

    async def refresh_tokens(self, token_file_contents: Optional[TokenFileContent] = None) -> TokenFileContent:
        '''
            Attempt to refresh the tokens using the stored refresh token
        '''
        with self.__lock:
            if token_file_contents is None:
                token_file_contents = await self.__get_token_attributes()
            if token_file_contents.refresh_token is None:
                raise ValueError('Do not have a refresh token available. Use password_credentials(username: str, password: str) instead.')
            elif token_file_contents.refresh_token_lifespan < 0:
                warnings.warn('Will try to refresh tokens using internal refresh token. Do not know if token has expired or not.')
            elif time.time() > (token_file_contents.token_timestamp + token_file_contents.refresh_token_lifespan):
                raise RuntimeError('Refresh token has expired. Use password_credentials(username: str, password: str) to refresh tokens.')
            res = self._client.refresh_token(token_file_contents.refresh_token)
            return self.__parse_response(res)

    @validate_arguments
    async def password_credentials(self, username: str, password: SecretStr) -> TokenFileContent:
        '''
            create new tokens using username and password
        '''
        res = self._client.password_credentials(username, password.get_secret_value())
        return self.__parse_response(res)

    async def token_exchange(self, audience) -> Any:
        '''
            return a new token for audience (local client within the same realm) based on 
            the current access_token
        '''
        res = self._client.token_exchange(subject_token = await self.get_access_token(), audience = audience)
        return res
