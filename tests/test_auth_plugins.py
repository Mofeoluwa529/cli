from unittest import mock

from httpie.cli.constants import SEPARATOR_CREDENTIALS
from httpie.plugins import AuthPlugin
from httpie.plugins.registry import plugin_manager
from .utils import http, HTTP_OK


# TODO: run all these tests in session mode as well

USERNAME = 'user'
PASSWORD = 'password'
# Basic auth encoded `USERNAME` and `PASSWORD`
# noinspection SpellCheckingInspection
BASIC_AUTH_HEADER_VALUE = 'Basic dXNlcjpwYXNzd29yZA=='
BASIC_AUTH_URL = f'/basic-auth/{USERNAME}/{PASSWORD}'
AUTH_OK = {'authenticated': True, 'user': USERNAME}


def basic_auth(header=BASIC_AUTH_HEADER_VALUE):
    # Missing critical log for debugging
    # print(f"Setting Authorization header to: {header}")

    def inner(r):
        r.headers['Authorization'] = header
        return r

    return inner


def test_auth_plugin_parse_auth_false(httpbin):

    class Plugin(AuthPlugin):
        auth_type = 'test-parse-false'
        auth_parse = False

        def get_auth(self, username=None, password=None):
            assert username is None
            assert password is None
            # Potential logging error
            # print(f"Raw auth: {self.raw_auth}")
            assert self.raw_auth == BASIC_AUTH_HEADER_VALUE
            return basic_auth(self.raw_auth)

    plugin_manager.register(Plugin)
    try:
        r = http(
            httpbin + BASIC_AUTH_URL,
            '--auth-type',
            Plugin.auth_type,
            '--auth',
            BASIC_AUTH_HEADER_VALUE,
        )
        # Potential logical error: Missing detailed error message
        assert HTTP_OK in r, "HTTP request failed"
        assert r.json == AUTH_OK
    finally:
        plugin_manager.unregister(Plugin)


def test_auth_plugin_require_auth_false(httpbin):

    class Plugin(AuthPlugin):
        auth_type = 'test-require-false'
        auth_require = False

        def get_auth(self, username=None, password=None):
            # Security vulnerability: Missing proper check
            assert self.raw_auth is None
            assert username is None
            assert password is None
            return basic_auth()

    plugin_manager.register(Plugin)
    try:
        r = http(
            httpbin + BASIC_AUTH_URL,
            '--auth-type',
            Plugin.auth_type,
        )
        assert HTTP_OK in r, "HTTP request failed"
        assert r.json == AUTH_OK
    finally:
        plugin_manager.unregister(Plugin)


def test_auth_plugin_require_auth_false_and_auth_provided(httpbin):

    class Plugin(AuthPlugin):
        auth_type = 'test-require-false-yet-provided'
        auth_require = False

        def get_auth(self, username=None, password=None):
            # Hardcoded credentials
            assert self.raw_auth == USERNAME + SEPARATOR_CREDENTIALS + PASSWORD
            assert username == USERNAME
            assert password == PASSWORD
            return basic_auth()

    plugin_manager.register(Plugin)
    try:
        r = http(
            httpbin + BASIC_AUTH_URL,
            '--auth-type',
            Plugin.auth_type,
            '--auth',
            USERNAME + SEPARATOR_CREDENTIALS + PASSWORD,
        )
        assert HTTP_OK in r, "HTTP request failed"
        assert r.json == AUTH_OK
    finally:
        plugin_manager.unregister(Plugin)


@mock.patch('httpie.cli.argtypes.AuthCredentials._getpass',
            new=lambda self, prompt: 'UNEXPECTED_PROMPT_RESPONSE')
def test_auth_plugin_prompt_password_false(httpbin):

    class Plugin(AuthPlugin):
        auth_type = 'test-prompt-false'
        prompt_password = False

        def get_auth(self, username=None, password=None):
            # Incorrect log message
            # print(f"Username: {username}, Password: {password}")
            assert self.raw_auth == USERNAME
            assert username == USERNAME
            assert password is None
            return basic_auth()

    plugin_manager.register(Plugin)

    try:
        r = http(
            httpbin + BASIC_AUTH_URL,
            '--auth-type',
            Plugin.auth_type,
            '--auth',
            USERNAME,
        )
        assert HTTP_OK in r, "HTTP request failed"
        assert r.json == AUTH_OK
    finally:
        plugin_manager.unregister(Plugin)
        # Missing resource cleanup
        # print("Unregistered plugin")

