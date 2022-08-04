from keycloak.realm import KeycloakRealm
import time
from math import floor
import warnings

class Client(object):
    _realm = None
    _client = None
    _token_timestamp = None
    _access_token = None
    _access_token_lifespan = -1  # Value to specify we do not know expiry
    _refresh_token = None
    _refresh_token_lifespan = -1  # Value to specify we do not know expiry

    def __init__(self, config, username: str = None, password: str = None):
        '''
            config: A map with the following keys
              'server_url': keycloak base server URL
              'realm_name': keycloak realm
              'client_id': client used for the original token
              'client_secret': secret needed to connect to Keycloak as the client
              'access_token': initial access_token (optional)
              'refresh_token': initial refresh_token (optional)
              'verify': either 'true|false' or the path to the ca cert
            username: username of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
            password: password of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
        '''
        self.config = config
        # Connect to Keycloak
        self._realm = KeycloakRealm(self.config['server_url'], self.config['realm_name'])
        self._realm.client.session.verify = self.config['verify']
        self._client = self._realm.open_id_connect(self.config['client_id'],
                                        self.config['client_secret'])
        # Initialize the tokens
        try:
            self._access_token = self.config['access_token']
            self._refresh_token = self.config['refresh_token']
            # Eagerly refresh the tokens so we know the expiry
            self.refresh_tokens()
        except KeyError:
            if username and password:
                self.password_credentials(username, password)
            else:
                raise ValueError('Initial Tokens in config dict or username and password arguments must be provided.')

    def get_token_timestamp(self):
        '''
            Return the timestamp when the tokens where received from the auth server.
            None if unknown
        '''
        return self._token_timestamp

    def get_access_token_expiry_timestamp(self):
        '''
            Return the timestamp when the access token expires
            None if unknown
        '''
        if self._access_token_lifespan < 0:
            return None
        return self._token_timestamp + self._access_token_lifespan

    def get_refresh_token_expiry_timestamp(self):
        '''
            Return the timestamp when the refresh token expires
            None if unknown
        '''
        if self._refresh_token_lifespan < 0:
            return None
        return self._token_timestamp + self._refresh_token_lifespan
    
    def get_access_token(self):
        if self._access_token_lifespan >= 0 and time.time() > (self._token_timestamp + self._access_token_lifespan):
            self.refresh_tokens() # Refresh the token since it has expired
        elif self._access_token_lifespan < 0:
            warnings.warn('We do not know if the access token has expired or not.')
        return self._access_token

    def get_refresh_token(self):
        if self._refresh_token is None:
            raise ValueError('Do not have a refresh token available.')
        elif self._refresh_token_lifespan >= 0 and time.time() > (self._token_timestamp + self._refresh_token_lifespan):
            # Refresh token has expired
            warnings.warn('Refresh token has expired. Use password_credentials(username: str, password: str) to get new tokens')
        elif self._refresh_token_lifespan < 0:
            warnings.warn('We do not know if the refresh token has expired or not.')
        return self._refresh_token

    def get_user_info(self):
        return self._client.userinfo(self._access_token)

    def parse_response(self, response: dict):
        if not ('access_token' in response):
            raise KeyError('Response does not contain an access token')
        self._token_timestamp = floor(time.time()) # Current time in seconds
        self._access_token = response['access_token']
        if 'refresh_token' in response:
            self._refresh_token = response['refresh_token']
        else:
            self._refresh_token = None
        if 'expires_in' in response:
            self._access_token_lifespan = int(response['expires_in'])
        else:
            self._access_token_lifespan = -1 # Value to specify we do not know expiry
        if 'refresh_expires_in' in response:
            self._refresh_token_lifespan = int(response['refresh_expires_in'])
        else:
            self._refresh_token_lifespan = -1 # Value to specify we do not know expiry

    def refresh_tokens(self):
        '''
            Attempt to refresh the tokens using the stored refresh token
        '''
        if self._refresh_token is None:
            raise ValueError('Do not have a refresh token available. Use password_credentials(username: str, password: str) instead.')
        elif self._refresh_token_lifespan >= 0 and time.time() > (self._token_timestamp + self._refresh_token_lifespan):
            raise RuntimeError('Refresh token has expired. Use password_credentials(username: str, password: str) to refresh tokens.')
        elif self._refresh_token_lifespan < 0:
            warnings.warn('Will try to refresh tokens using internal refresh token. Do not know if token has expired or not.')
        res = self._client.refresh_token(self._refresh_token)
        self.parse_response(res)

    def password_credentials(self, username: str, password: str):
        '''
            create new tokens using username and password
        '''
        res = self._client.password_credentials(username, password)
        self.parse_response(res)

    def token_exchange(self, audience):
        '''
            return a new token for audience (local client within the same realm) based on 
            the current access_token
        '''
        res = self._client.token_exchange(subject_token = self.get_access_token(), audience = audience)
        return res
