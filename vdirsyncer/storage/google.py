from __future__ import annotations

import json
import logging
import os
import asyncio
import wsgiref.simple_server
from pathlib import Path
from threading import Thread
from urllib import parse as urlparse
from threading import Thread

import aiohttp
import click

from vdirsyncer import exceptions
from vdirsyncer.utils import atomic_write
from vdirsyncer.utils import checkdir
from vdirsyncer.utils import expand_path
from vdirsyncer.utils import open_graphical_browser

from . import base
from . import dav
from .google_helpers import _RedirectWSGIApp
from .google_helpers import _WSGIRequestHandler

logger = logging.getLogger(__name__)


TOKEN_URL = "https://accounts.google.com/o/oauth2/v2/auth"
REFRESH_URL = "https://oauth2.googleapis.com/token"

try:
    from aiohttp_oauthlib import OAuth2Session

    have_oauth2 = True
except ImportError:
    have_oauth2 = False


class GoogleSession(dav.DAVSession):
    def __init__(
        self,
        token_file,
        client_id,
        client_secret,
        url=None,
        *,
        connector: aiohttp.BaseConnector,
    ):
        if not have_oauth2:
            raise exceptions.UserError("aiohttp-oauthlib not installed")

        # Required for discovering collections
        if url is not None:
            self.url = url

        self.useragent = client_id
        self._settings = {}
        self.connector = connector

        self._token_file = Path(expand_path(token_file))
        self._client_id = client_id
        self._client_secret = client_secret
        self._token = None
        self._redirect_uri = None

    async def request(self, method, path, **kwargs):
        if not self._token:
            await self._init_token()

        return await super().request(method, path, **kwargs)

    def _save_token(self, token):
        """Helper function called by OAuth2Session when a token is updated."""
        # Update in-memory token immediately so subsequent sessions use it.
        self._token = token
        checkdir(expand_path(os.path.dirname(self._token_file)), create=True)
        with atomic_write(self._token_file, mode="w", overwrite=True) as f:
            json.dump(token, f)

    @property
    def _session(self):
        """Return a new OAuth session for requests.

        Accesses the self.redirect_uri field (str): the URI to redirect
        authentication to. Should be a loopback address for a local server that
        follows the process detailed in
        https://developers.google.com/identity/protocols/oauth2/native-app.
        """

        return OAuth2Session(
            client_id=self._client_id,
            token=self._token,
            redirect_uri=self._redirect_uri,
            scope=self.scope,
            auto_refresh_url=REFRESH_URL,
            auto_refresh_kwargs={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            token_updater=self._save_token,
            connector=self.connector,
            connector_owner=False,
            trust_env=True,
        )

    async def _init_token(self):
        # A simple, process-local lock per token file path to avoid
        # kicking off multiple OAuth flows concurrently when multiple
        # GoogleSession instances are created at the same time.
        global _TOKEN_INIT_LOCKS
        try:
            _TOKEN_INIT_LOCKS
        except NameError:
            _TOKEN_INIT_LOCKS = {}

        def _load_token_from_file():
            try:
                with self._token_file.open() as f:
                    return json.load(f)
            except FileNotFoundError:
                return None
            except ValueError as e:
                raise exceptions.UserError(
                    f"Failed to load token file {self._token_file}, try deleting it. "
                    f"Original error: {e}"
                )

        # Fast path: try to load an existing token without taking the lock.
        self._token = _load_token_from_file()
        if self._token:
            return

        # Acquire a per-token-file asyncio lock to serialize the OAuth flow.
        lock_key = str(self._token_file.resolve())
        lock = _TOKEN_INIT_LOCKS.get(lock_key)
        if lock is None:
            lock = _TOKEN_INIT_LOCKS[lock_key] = asyncio.Lock()

        async with lock:
            # Double-check after acquiring the lock in case another task
            # completed the flow while we were waiting.
            self._token = _load_token_from_file()
            if self._token:
                return

            # Start the local redirect server and run the OAuth flow.
            wsgi_app = _RedirectWSGIApp("Successfully obtained token.")
            wsgiref.simple_server.WSGIServer.allow_reuse_address = False
            host = "127.0.0.1"
            local_server = wsgiref.simple_server.make_server(
                host, 0, wsgi_app, handler_class=_WSGIRequestHandler
            )
            thread = Thread(target=local_server.handle_request)
            thread.start()
            self._redirect_uri = f"http://{host}:{local_server.server_port}"

            try:
                async with self._session as session:
                    authorization_url, state = session.authorization_url(
                        TOKEN_URL,
                        # access_type and prompt are Google specific
                        # extra parameters.
                        access_type="offline",
                        prompt="consent",
                    )
                    click.echo(f"Opening {authorization_url} ...")
                    try:
                        open_graphical_browser(authorization_url)
                    except Exception as e:
                        logger.warning(str(e))

                    click.echo("Follow the instructions on the page.")
                    thread.join()
                    logger.debug("server handled request!")

                    # Note: using https here because oauthlib is very picky that
                    # OAuth 2.0 should only occur over https.
                    authorization_response = wsgi_app.last_request_uri.replace(
                        "http", "https", 1
                    )
                    logger.debug(
                        f"authorization_response: {authorization_response}"
                    )

                    # Exchange authorization code for tokens
                    self._token = await session.fetch_token(
                        REFRESH_URL,
                        authorization_response=authorization_response,
                        # Google specific extra param used for client authentication:
                        client_secret=self._client_secret,
                    )
                    logger.debug(f"token: {self._token}")
            finally:
                # Always close the local server to free the port.
                local_server.server_close()

            # Persist token after successful fetch so that concurrent sessions
            # can immediately reuse it.
            self._save_token(self._token)


class GoogleCalendarStorage(dav.CalDAVStorage):
    class session_class(GoogleSession):
        url = "https://apidata.googleusercontent.com/caldav/v2/"
        scope = ["https://www.googleapis.com/auth/calendar"]

    class discovery_class(dav.CalDiscover):
        @staticmethod
        def _get_collection_from_url(url):
            # Google CalDAV has collection URLs like:
            # /user/foouser/calendars/foocalendar/events/
            parts = url.rstrip("/").split("/")
            parts.pop()
            collection = parts.pop()
            return urlparse.unquote(collection)

    storage_name = "google_calendar"

    def __init__(
        self,
        token_file,
        client_id,
        client_secret,
        start_date=None,
        end_date=None,
        item_types=(),
        **kwargs,
    ):
        if not kwargs.get("collection"):
            raise exceptions.CollectionRequired

        super().__init__(
            token_file=token_file,
            client_id=client_id,
            client_secret=client_secret,
            start_date=start_date,
            end_date=end_date,
            item_types=item_types,
            **kwargs,
        )

    # This is ugly: We define/override the entire signature computed for the
    # docs here because the current way we autogenerate those docs are too
    # simple for our advanced argspec juggling in `vdirsyncer.storage.dav`.
    __init__._traverse_superclass = base.Storage  # type: ignore


class GoogleContactsStorage(dav.CardDAVStorage):
    class session_class(GoogleSession):
        # Google CardDAV is completely bonkers. Collection discovery doesn't
        # work properly, well-known URI takes us directly to single collection
        # from where we can't discover principal or homeset URIs (the PROPFINDs
        # 404).
        #
        # So we configure the well-known URI here again, such that discovery
        # tries collection enumeration on it directly. That appears to work.
        url = "https://www.googleapis.com/.well-known/carddav"
        scope = ["https://www.googleapis.com/auth/carddav"]

    class discovery_class(dav.CardDiscover):
        # Google CardDAV doesn't return any resourcetype prop.
        _resourcetype = None

    storage_name = "google_contacts"

    def __init__(self, token_file, client_id, client_secret, **kwargs):
        if not kwargs.get("collection"):
            raise exceptions.CollectionRequired

        super().__init__(
            token_file=token_file,
            client_id=client_id,
            client_secret=client_secret,
            **kwargs,
        )

    # This is ugly: We define/override the entire signature computed for the
    # docs here because the current way we autogenerate those docs are too
    # simple for our advanced argspec juggling in `vdirsyncer.storage.dav`.
    __init__._traverse_superclass = base.Storage  # type: ignore
