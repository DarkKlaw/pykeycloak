# PyKeycloak
Client library to simplify token access 

This package uses [python-keycloak](https://github.com/marcospereirampj/python-keycloak) as a base for now and provides a much simpler APIs for our needs.```

## In-memory token (and synchronous) client 

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

## File token (and asynchronous) client 

This client saves the token in a file.
This allows the same tokens to be shared by multiple clients.
To ensure proper synchronization of the token, a file lock is used to access the file.
This means the client becomes asynchronous since it has to wait for the lock.

```
import os
from pykeycloak import SharedTokenClient

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
client = SharedTokenClient(config)

# Initialize the tokens
await client.initialize_tokens()

# get current access token, and current refresh token
await client.get_access_token()
await client.get_refresh_token()

# obtain new access token
await client.refresh_tokens()

# get user info
await client.get_user_info()

# get token for another audience
tokens = await client.token_exchange('another-client')
```
