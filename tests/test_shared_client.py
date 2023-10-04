import os
from typing import Optional, Tuple
from pydantic import SecretStr, ValidationError
from unittest.mock import patch, Mock, MagicMock
from tempfile import TemporaryDirectory
import pytest
import json

pytest_plugins = ('pytest_asyncio',)

from src.pykeycloak.shared_client import SharedTokenClient
from src.pykeycloak.models import ClientConfig, TokenFileContent

def initialize_test_client(
    config: ClientConfig
) -> Tuple[SharedTokenClient, Mock]:
    mock_client = MagicMock()
    # Initialize the Client
    client = SharedTokenClient(config, client=mock_client)
    # Return the client (and the mock Keycloak Client)
    return client, mock_client
    
def initialize_token_file(
    token_filename: str,
    token_file_contents: TokenFileContent
):
    with open(token_filename, 'w') as token_file:
        json.dump(token_file_contents.to_jsonable_dict(), token_file)
    
@pytest.mark.asyncio
async def test_client_initialization_with_creds():
    with TemporaryDirectory() as tmp_dir:
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        # Initialize the Client
        client, mock_client = initialize_test_client(config)
        # Set the return value
        mock_client.token.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        # Initialize the tokens
        token_content = await client.initialize_tokens(
            username='test',
            password='password'
        )
        assert os.path.exists(f'{tmp_dir}/test_realm.tok')
        assert os.path.exists(f'{tmp_dir}/test_realm.lock')
        assert token_content.access_token == 'access_token'
        assert token_content.refresh_token == 'refresh_token'

@pytest.mark.asyncio
async def test_client_initialization_with_config_tokens():
    with TemporaryDirectory() as tmp_dir:
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok',
            access_token='initial access token',
            refresh_token='initial refresh token'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.refresh_token.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        # Initialize the tokens
        token_content = await client.initialize_tokens()
        assert os.path.exists(f'{tmp_dir}/test_realm.tok')
        assert os.path.exists(f'{tmp_dir}/test_realm.lock')
        assert token_content.access_token != 'initial access token'
        assert token_content.access_token == 'access_token'
        assert token_content.refresh_token != 'initial refresh token'
        assert token_content.refresh_token == 'refresh_token'

@pytest.mark.asyncio
async def test_client_initialization_with_existing_file():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.refresh_token.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
        assert os.path.exists(f'{tmp_dir}/test_realm.tok')
        assert os.path.exists(f'{tmp_dir}/test_realm.lock')
        assert token_content.access_token == 'initial access token'
        assert token_content.access_token != 'access_token'
        assert token_content.refresh_token == 'initial refresh token'
        assert token_content.refresh_token != 'refresh_token'

@pytest.mark.asyncio
async def test_client_initialization_with_expired_access_existing_file():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.refresh_token.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1700
            # Initialize the tokens
            token_content = await client.initialize_tokens()
        assert os.path.exists(f'{tmp_dir}/test_realm.tok')
        assert os.path.exists(f'{tmp_dir}/test_realm.lock')
        assert token_content.access_token != 'initial access token'
        assert token_content.access_token == 'access_token'
        assert token_content.refresh_token != 'initial refresh token'
        assert token_content.refresh_token == 'refresh_token'

@pytest.mark.asyncio
async def test_client_initialization_with_expired_access_existing_file():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.refresh_token.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1700
            # Initialize the tokens
            token_content = await client.initialize_tokens()
        assert os.path.exists(f'{tmp_dir}/test_realm.tok')
        assert os.path.exists(f'{tmp_dir}/test_realm.lock')
        assert token_content.access_token != 'initial access token'
        assert token_content.access_token == 'access_token'
        assert token_content.refresh_token != 'initial refresh token'
        assert token_content.refresh_token == 'refresh_token'

@pytest.mark.asyncio
async def test_client_initialization_with_expired_existing_file_with_creds():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.token.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 600,
            'refresh_expires_in': 1800
        }
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 10000
            # Initialize the tokens
            token_content = await client.initialize_tokens(
                username='test',
                password='password'
            )
        assert os.path.exists(f'{tmp_dir}/test_realm.tok')
        assert os.path.exists(f'{tmp_dir}/test_realm.lock')
        assert token_content.access_token != 'initial access token'
        assert token_content.access_token == 'access_token'
        assert token_content.refresh_token != 'initial refresh token'
        assert token_content.refresh_token == 'refresh_token'

@pytest.mark.asyncio
async def test_client_initialization_with_expired_existing_file_no_creds():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 10000
            with pytest.raises(RuntimeError) as exc_info:
                # Initialize the tokens
                token_content = await client.initialize_tokens()
        assert exc_info.value.args[0] == 'Refresh token has expired. Use password_credentials(username: str, password: str) to refresh tokens.'

@pytest.mark.asyncio
async def test_client_initialization_parser_error():
    with TemporaryDirectory() as tmp_dir:
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.token.return_value = {}
        with pytest.raises(KeyError) as exc_info:
            token_content = await client.initialize_tokens(
                username='test',
                password='password'
            )
        assert exc_info.value.args[0] == 'Response does not contain an access token'

@pytest.mark.asyncio
async def test_client_initialization_parser_error_2():
    with TemporaryDirectory() as tmp_dir:
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok',
            access_token='initial access token',
            refresh_token='initial refresh token'
        )
        client, mock_client = initialize_test_client(config)
        mock_client.refresh_token.return_value = {}
        # Initialize the tokens
        with pytest.raises(KeyError) as exc_info:
            token_content = await client.initialize_tokens()
        assert exc_info.value.args[0] == 'Response does not contain an access token'

@pytest.mark.asyncio
async def test_client_get_token_timestamp():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
        token_timestamp = await client.get_token_timestamp()
        assert token_timestamp == 1000

@pytest.mark.asyncio
async def test_client_get_access_token_expiry_timestamp():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
        token_expiry_timestamp = await client.get_access_token_expiry_timestamp()
        assert token_expiry_timestamp == 1600

@pytest.mark.asyncio
async def test_client_get_refresh_token_expiry_timestamp():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
        token_expiry_timestamp = await client.get_refresh_token_expiry_timestamp()
        assert token_expiry_timestamp == 2800

@pytest.mark.asyncio
async def test_client_get_access_token():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
            access_token = await client.get_access_token()
        assert access_token == 'initial access token'

@pytest.mark.asyncio
async def test_client_get_refresh_token():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
            refresh_token = await client.get_refresh_token()
        assert refresh_token == 'initial refresh token'

@pytest.mark.asyncio
async def test_client_user_info():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
            mock_client.userinfo.return_value = 'User Info'
            assert await client.get_user_info() == 'User Info'

@pytest.mark.asyncio
async def test_client_token_exchange():
    with TemporaryDirectory() as tmp_dir:
        # Generate the existing token file
        initialize_token_file(
            f'{tmp_dir}/test_realm.tok',
            TokenFileContent(
                server_url='https://example.com',
                realm_name='test_realm',
                token_timestamp=1000,
                access_token='initial access token',
                access_token_lifespan=600,
                refresh_token='initial refresh token',
                refresh_token_lifespan=1800
            )
        )
        config: ClientConfig = ClientConfig(
            server_url='https://example.com',
            realm_name='test_realm',
            client_id='test_client',
            client_secret='client_secret',
            token_filename=f'{tmp_dir}/test_realm.tok'
        )
        client, mock_client = initialize_test_client(config)
        with patch('time.time', autospec=True) as mock_time:
            mock_time.return_value = 1100
            # Initialize the tokens
            token_content = await client.initialize_tokens()
            mock_client.exchange_token.return_value = 'Token exchanged'
            assert await client.token_exchange('test') == 'Token exchanged'