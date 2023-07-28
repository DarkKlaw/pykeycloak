from typing import Optional, Tuple
from pydantic import SecretStr, ValidationError
from unittest.mock import patch, Mock, MagicMock
import pytest

from src.pykeycloak.client import Client
from src.pykeycloak.models import ClientConfig

def initialize_test_client(
    config: ClientConfig, 
    username: Optional[str] = None, 
    password: Optional[SecretStr] = None,
    mock_token_response: dict = {
        'access_token': 'access_token',
        'refresh_token': 'refresh_token',
        'expires_in': 600,
        'refresh_expires_in': 1800
    },
    init_access_token: Optional[str] = None,
    init_refresh_token: Optional[str] = None
) -> Tuple[Client, Mock]:
    mock_client = MagicMock()
    with patch('src.pykeycloak.client.KeycloakRealm', autospec=True) as mock_realm:
        mock_realm_value = mock_realm.return_value
        mock_realm_value.open_id_connect.return_value = mock_client
        if init_access_token is not None and init_refresh_token is not None:
            config.access_token = init_access_token
            config.refresh_token = init_refresh_token
            # Patch necessary function(s) to test refresh_tokens
            mock_client.refresh_token.return_value = mock_token_response
        elif username is not None and password is not None:
            # Patch necessary function(s) to test password_credentials
            mock_client.password_credentials.return_value = mock_token_response
        # Initialize the Client
        client = Client(config, username = username, password = password)
        # Return the client (and the mock Keycloak Client)
        return client, mock_client
    
def test_client_init_with_refresh():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    client, mock_client = initialize_test_client(
        config,
        init_access_token='initial access token',
        init_refresh_token='initial refresh token'
    )
    assert client.get_access_token() != 'initial access token'
    assert client.get_access_token() == 'access_token'
    assert client.get_refresh_token() != 'initial refresh token'
    assert client.get_refresh_token() == 'refresh_token'

def test_client_init_with_creds():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    client, mock_client = initialize_test_client(
        config,
        username='test',
        password='password'
    )
    assert client.get_access_token() == 'access_token'
    assert client.get_refresh_token() == 'refresh_token'

def test_client_init_with_insufficient_info():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    with pytest.raises(ValueError) as exc_info:
        client, mock_client = initialize_test_client(
            config
        )
    assert exc_info.value.args[0] == 'Initial Tokens in config dict or username and password arguments must be provided.'

def test_client_init_with_validation_error():
    config: ClientConfig = {
        'realm_name': 'test_realm',
        'client_id': 'test_client',
        'client_secret': 'client_secret'
    }
    with pytest.raises(ValidationError) as exc_info:
        client, mock_client = initialize_test_client(
            config
        )

def test_client_timestamps_getters():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    with patch('time.time', autospec=True) as mock_time:
        mock_time.return_value = 1000
        client, mock_client = initialize_test_client(
            config,
            username='test',
            password='password'
        )
        assert client.get_token_timestamp() == 1000
        assert client.get_access_token_expiry_timestamp() == 1600
        assert client.get_refresh_token_expiry_timestamp() == 2800

def test_client_parser_error():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    with pytest.raises(KeyError) as exc_info:
        client, mock_client = initialize_test_client(
            config,
            username='test',
            password='password',
            mock_token_response={}
        )
    assert exc_info.value.args[0] == 'Response does not contain an access token'

def test_client_user_info():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    client, mock_client = initialize_test_client(
        config,
        username='test',
        password='password'
    )
    mock_client.userinfo.return_value = 'User Info'
    assert client.get_user_info() == 'User Info'

def test_client_token_exchange():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    client, mock_client = initialize_test_client(
        config,
        username='test',
        password='password'
    )
    mock_client.token_exchange.return_value = 'Token exchanged'
    assert client.token_exchange('test') == 'Token exchanged'

def test_client_autorefresh_on_expired_access_token_get():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    with patch('time.time', autospec=True) as mock_time:
        mock_time.return_value = 1000
        client, mock_client = initialize_test_client(
            config,
            username='test',
            password='password'
        )
        mock_time.return_value = 2400
        mock_client.refresh_token.return_value = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        access_token = client.get_access_token()
        assert access_token != 'access_token'
        assert access_token == 'new_access_token'
        assert client.get_refresh_token() != 'refresh_token'
        assert client.get_refresh_token() == 'new_refresh_token'

def test_client_refresh_refusal_on_expired_access_token_get():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    with patch('time.time', autospec=True) as mock_time:
        mock_time.return_value = 1000
        client, mock_client = initialize_test_client(
            config,
            username='test',
            password='password'
        )
        mock_time.return_value = 10000
        mock_client.refresh_token.return_value = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        with pytest.raises(RuntimeError) as exc_info:
            client.get_access_token()
        assert exc_info.value.args[0] == 'Refresh token has expired. Use password_credentials(username: str, password: str) to refresh tokens.'

def test_client_refresh_failure_no_token():
    config: ClientConfig = ClientConfig(
        server_url='https://example.com',
        realm_name='test_realm',
        client_id='test_client',
        client_secret='client_secret'
    )
    client, mock_client = initialize_test_client(
        config,
        username='test',
        password='password',
        mock_token_response={
            'access_token': 'new_access_token',
            'expires_in': 600
        }
    )
    with pytest.raises(ValueError) as exc_info:
        client.refresh_tokens()
    assert exc_info.value.args[0] == 'Do not have a refresh token available. Use password_credentials(username: str, password: str) instead.'