# PyKeycloak
Client library to simplify token access 

This package use [python-keycloak-client](https://github.com/Peter-Slump/python-keycloak-client) as a base for now and provide a much simmpler APIs for our needs.```

```
import os
from pykeycloak import Client

# initial configuration
config = {
    'server_url':    'https://keycloak.company.com',
    'realm_name':    'my-realm',
    'client_id':     'my-client',
    'client_secret':  <redacted>,
    'access_token':  os.environ['ACCESS_TOKEN'],
    'refresh_token': os.environ['REFRESH_TOKEN'],
    'verify':        '/etc/ssl/certs/ca-certificates.crt',
}

# create a client
client = Client(config)

# get current access token, and current refresh token
client.get_access_token()
client.get_refresh_token()

# obtain new access token
client.refresh_tokens()

# get user info
client.get_user_info()

# get token for another audience
tokens = client.token_exchange('another-client')
```
