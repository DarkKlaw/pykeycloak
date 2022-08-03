from keycloak.realm import KeycloakRealm

class Client(object):

    _realm = None
    _client = None
    _access_token = None
    _refresh_token = None

    def __init__(self, config, username: str = None, password: str = None):
        '''
            config: A map with the following keys
              'server_url': keycloak base server URL
              'realm_name': keycloak realm
              'client_id': client used for the original token
              'client_secret':
              'access_token': initial access_token (optional)
              'refresh_token': initial refresh_token (optional)
              'verify': either 'true|false' or the path to the ca cert
            username: username of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
            password: password of the user we want to get the token for (if config['access_token'] and config['refresh_token'] are not given)
        '''
        self.config = config
        
        self._realm = KeycloakRealm(self.config['server_url'], self.config['realm_name'])
        self._realm.client.session.verify = self.config['verify']

        self._client = self._realm.open_id_connect(self.config['client_id'],
                                        self.config['client_secret'])
        try:
            self._access_token = self.config['access_token']
            self._refresh_token = self.config['refresh_token']
        except KeyError:
            if username and password:
                res = self._client.password_credentials(username, password)
                self._access_token = res['access_token']
                self._refresh_token = res['refresh_token']
            else:
                raise ValueError('Initial Tokens in config dict or username and password arguments must be provided.')

    def get_access_token(self):
        '''
            TBD: check the validity of the access token and refresh it if needed
        '''
        return self._access_token

    def get_refresh_token(self):

        return self._refresh_token

    def get_user_info(self):
        return self._client.userinfo(self.get_access_token())

    def refresh_tokens(self):
        res = self._client.refresh_token(self.get_refresh_token())
        self._access_token = res['access_token']
        self._refresh_token = res['refresh_token']

    def password_credentials(self, username: str, password: str):
        '''
            create new tokens using username and password
        '''
        res = self._client.password_credentials(username, password)
        self._access_token = res['access_token']
        self._refresh_token = res['refresh_token']

    def token_exchange(self, audience):
        '''
            return a new token for audience (local client within the same realm) based on 
            the current access_token
        '''
        res = self._client.token_exchange(subject_token = self.get_access_token(), audience = audience)
        return res
