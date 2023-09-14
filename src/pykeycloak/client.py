from typing import Optional, Union, Any
from pydantic import SecretStr, HttpUrl, validate_arguments, parse_obj_as
from keycloak import KeycloakOpenID
import time
import warnings

from .models import ClientConfig, TokenFileContent

class Client(object):
    _client: KeycloakOpenID
    _token_info: TokenFileContent

    @validate_arguments(config=dict(arbitrary_types_allowed=True))
    def __init__(
        self, 
        config: ClientConfig, 
        client: Optional[Any] = None,
        username: Optional[str] = None, 
        password: Optional[SecretStr] = None
    ):
        '''
            config: A map with the following keys
              'server_url': keycloak base server URL
              'realm_name': keycloak realm
              'client_id': client used for the original token
              'client_secret': secret needed to connect to Keycloak as the client
              'access_token': initial access_token (optional)
              'refresh_token': initial refresh_token (optional)
              'verify': either 'true|false' or the path to the ca cert. Defaults to True
            client: Keycloak client to use instead of initializing one with the supplied config. Mainly for testing purposes.
            username: username of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
            password: password of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
        '''
        self.config = config.copy(deep=True)
        str_url = str(self.config.server_url)
        # Verify the server_url (Ensure its ends with /auth/)
        if str_url.endswith('/auth'):
            str_url += '/'
        elif not str_url.endswith('/auth/'):
            if str_url.endswith('/'):
                str_url += 'auth/'
            else:
                str_url += '/auth/'
        # Override the config url
        self.config.server_url = parse_obj_as(HttpUrl, str_url)
        # Connect to Keycloak
        if client is None:
            self._client = KeycloakOpenID(
                server_url=str(self.config.server_url),
                client_id=self.config.client_id,
                realm_name=self.config.realm_name,
                client_secret_key=self.config.client_secret.get_secret_value(),
                verify=self.config.verify
            )
        else:
            self._client = client
        # Initialize the tokens
        self._token_info = TokenFileContent(
            server_url=self.config.server_url,
            realm_name=self.config.realm_name,
            token_timestamp=time.time(),
            access_token=''
        )
        if self.config.access_token is not None and self.config.refresh_token is not None:
            self._token_info.access_token = self.config.access_token
            self._token_info.refresh_token = self.config.refresh_token
            # Eagerly refresh the tokens so we know the expiry
            self._token_info = self.refresh_tokens()
        elif username and password:
            self._token_info = self.password_credentials(username, password)
        else:
            raise ValueError('Initial Tokens in config dict or username and password arguments must be provided.')

    def get_token_timestamp(self) -> float:
        '''
            Return the timestamp when the tokens where received from the auth server.
            None if unknown
        '''
        return self._token_info.token_timestamp

    def get_access_token_expiry_timestamp(self) -> float:
        '''
            Return the timestamp when the access token expires
            None if unknown
        '''
        if self._token_info.access_token_lifespan < 0:
            return None
        return self._token_info.token_timestamp + self._token_info.access_token_lifespan

    def get_refresh_token_expiry_timestamp(self) -> float:
        '''
            Return the timestamp when the refresh token expires
            None if unknown
        '''
        if self._token_info.refresh_token_lifespan < 0:
            return None
        return self._token_info.token_timestamp + self._token_info.refresh_token_lifespan
    
    def get_access_token(self) -> str:
        if self._token_info.access_token_lifespan < 0:
            warnings.warn('We do not know if the access token has expired or not.')
        elif time.time() > (self._token_info.token_timestamp + self._token_info.access_token_lifespan):
            self._token_info = self.refresh_tokens() # Refresh the token since it has expired
        return self._token_info.access_token

    def get_refresh_token(self) -> Union[str, None]:
        if self._token_info.refresh_token is None:
            raise None
        elif self._token_info.refresh_token_lifespan < 0:
            warnings.warn('We do not know if the refresh token has expired or not.')
        elif time.time() > (self._token_info.token_timestamp + self._token_info.refresh_token_lifespan):
            # Refresh token has expired
            warnings.warn('Refresh token has expired. Use password_credentials(username: str, password: str) to get new tokens')
            return None
        return self._token_info.refresh_token

    def get_user_info(self) -> Any:
        return self._client.userinfo(self._token_info.access_token)

    def parse_response(self, response: dict) -> TokenFileContent:
        if not ('access_token' in response):
            raise KeyError('Response does not contain an access token')
        self._token_info.token_timestamp = time.time() # Current time in seconds
        self._token_info.access_token = response['access_token']
        if 'refresh_token' in response:
            self._token_info.refresh_token = response['refresh_token']
        else:
            self._token_info.refresh_token = None
        if 'expires_in' in response:
            self._token_info.access_token_lifespan = int(response['expires_in'])
        else:
            self._token_info.access_token_lifespan = -1 # Value to specify we do not know expiry
        if 'refresh_expires_in' in response:
            self._token_info.refresh_token_lifespan = int(response['refresh_expires_in'])
        else:
            self._token_info.refresh_token_lifespan = -1 # Value to specify we do not know expiry
        return self._token_info.copy()

    def refresh_tokens(self) -> TokenFileContent:
        '''
            Attempt to refresh the tokens using the stored refresh token
        '''
        if self._token_info.refresh_token is None:
            raise ValueError('Do not have a refresh token available. Use password_credentials(username: str, password: str) instead.')
        elif self._token_info.refresh_token_lifespan >= 0 and time.time() > (self._token_info.token_timestamp + self._token_info.refresh_token_lifespan):
            raise RuntimeError('Refresh token has expired. Use password_credentials(username: str, password: str) to refresh tokens.')
        elif self._token_info.refresh_token_lifespan < 0:
            warnings.warn('Will try to refresh tokens using internal refresh token. Do not know if token has expired or not.')
        res = self._client.refresh_token(self._token_info.refresh_token)
        return self.parse_response(res)

    @validate_arguments
    def password_credentials(self, username: str, password: SecretStr) -> TokenFileContent:
        '''
            create new tokens using username and password
        '''
        res = self._client.token(
            username = username, 
            password = password.get_secret_value()
        )
        return self.parse_response(res)

    def token_exchange(self, audience) -> Any:
        '''
            return a new token for audience (local client within the same realm) based on 
            the current access_token
        '''
        res = self._client.exchange_token(self.get_access_token(), audience)
        return res