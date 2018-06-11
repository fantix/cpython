import collections
import warnings
try:
    import ssl
except ImportError:  # pragma: no cover
    ssl = None

from . import base_events
from . import constants
from . import protocols
from . import transports
from .log import logger


def _create_transport_context(server_side, server_hostname):
    if server_side:
        raise ValueError('Server side SSL needs a valid SSLContext')

    # Client side may pass ssl=True to use a default
    # context; in that case the sslcontext passed is None.
    # The default is secure for client connections.
    # Python 3.4+: use up-to-date strong settings.
    sslcontext = ssl.create_default_context()
    if not server_hostname:
        sslcontext.check_hostname = False
    return sslcontext


# States of an _SSLPipe.
_UNWRAPPED = "UNWRAPPED"
_DO_HANDSHAKE = "DO_HANDSHAKE"
_WRAPPED = "WRAPPED"
_SHUTDOWN = "SHUTDOWN"


class _SSLTransport(transports._FlowControlMixin, transports.Transport):
    def __init__(self, loop, ssl_protocol):
        self._loop = loop
        # SSLProtocol instance
        self._ssl_protocol = ssl_protocol
        self._closed = False

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        return self._ssl_protocol._get_extra_info(name, default)

    def write(self, data):
        self._ssl_protocol._do_write(data)


class SSLProtocol(protocols.BufferedProtocol):
    def __init__(self, loop, app_protocol, sslcontext, waiter,
                 server_side=False, server_hostname=None,
                 call_connection_made=True,
                 ssl_handshake_timeout=None):
        if ssl is None:
            raise RuntimeError('stdlib ssl module not available')

        if ssl_handshake_timeout is None:
            ssl_handshake_timeout = constants.SSL_HANDSHAKE_TIMEOUT
        elif ssl_handshake_timeout <= 0:
            raise ValueError(
                f"ssl_handshake_timeout should be a positive number, "
                f"got {ssl_handshake_timeout}")

        if not sslcontext:
            sslcontext = _create_transport_context(
                server_side, server_hostname)

        self._waiter = waiter
        self._app_transport = _SSLTransport(loop, self)
        self._app_protocol = app_protocol
        self._server_side = server_side
        if server_hostname and not server_side:
            self._server_hostname = server_hostname
        else:
            self._server_hostname = None
        self._sslcontext = sslcontext
        # SSL-specific extra info. More info are set when the handshake
        # completes.
        self._extra = dict(sslcontext=sslcontext)

        self._sslobj = None
        self._transport = None
        self._state = _UNWRAPPED
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl_buffer = bytearray(262144)

    # BaseProtocol methods

    def connection_made(self, transport):
        self._transport = transport
        self._start_handshake()

    def connection_lost(self, exc):
        pass

    def pause_writing(self):
        """Called when the low-level transport's buffer goes over
        the high-water mark.
        """
        self._app_protocol.pause_writing()

    def resume_writing(self):
        """Called when the low-level transport's buffer drains below
        the low-water mark.
        """
        self._app_protocol.resume_writing()

    # BufferedProtocol methods

    def get_buffer(self, n):
        return self._ssl_buffer

    def buffer_updated(self, nbytes):
        incoming = memoryview(self._ssl_buffer)[:nbytes]
        # print('<', bytes(incoming))
        self._incoming.write(incoming)

        if self._state == _DO_HANDSHAKE:
            self._do_handshake()
        elif self._state == _WRAPPED:
            self._do_read()

    def eof_received(self):
        self._app_protocol.eof_received()

    # old

    def _wakeup_waiter(self, exc=None):
        if self._waiter is None:
            return
        if not self._waiter.cancelled():
            if exc is not None:
                self._waiter.set_exception(exc)
            else:
                self._waiter.set_result(None)
        self._waiter = None

    def _get_extra_info(self, name, default=None):
        if name in self._extra:
            return self._extra[name]
        elif self._transport is not None:
            return self._transport.get_extra_info(name, default)
        else:
            return default

    # Internal methods

    def _set_state(self, new_state):
        if self._state == _UNWRAPPED and new_state == _DO_HANDSHAKE:
            self._state = new_state

        elif self._state == _DO_HANDSHAKE and new_state == _WRAPPED:
            self._state = new_state

        else:
            raise RuntimeError(
                'cannot switch to state {}; '
                'another operation ({}) is in progress'.format(
                    new_state, self._state))

    def _start_handshake(self):
        self._set_state(_DO_HANDSHAKE)

        self._sslobj = self._sslcontext.wrap_bio(
            self._incoming, self._outgoing,
            server_side=self._server_side,
            server_hostname=self._server_hostname)
        self._do_handshake()

    def _do_handshake(self):
        try:
            self._sslobj.do_handshake()
        except ssl.SSLError as exc:
            if exc.errno not in (ssl.SSL_ERROR_WANT_READ,
                                 ssl.SSL_ERROR_WANT_WRITE,
                                 ssl.SSL_ERROR_SYSCALL):
                raise
        else:
            self._set_state(_WRAPPED)
            self._app_protocol.connection_made(self._app_transport)
            self._wakeup_waiter()
        if self._outgoing.pending:
            out = self._outgoing.read()
            if out:
                # print('>', out)
                self._transport.write(out)

    def _do_write(self, data):
        view = memoryview(data)
        offset = 0
        size = len(view)
        out = []
        while offset < size:
            try:
                offset += self._sslobj.write(view[offset:])
            except ssl.SSLError as exc:
                if exc.errno not in (ssl.SSL_ERROR_WANT_READ,
                                     ssl.SSL_ERROR_WANT_WRITE,
                                     ssl.SSL_ERROR_SYSCALL):
                    raise
                if exc.errno == ssl.SSL_ERROR_WANT_READ:
                    break

            if self._outgoing.pending:
                out.append(self._outgoing.read())
        if out:
            # print('>', out)
            self._transport.writelines(out)

    def _do_read(self):
        data = []
        try:
            while True:
                chunk = self._sslobj.read(16384)
                if not chunk:
                    break
                data.append(chunk)
        except ssl.SSLError as exc:
            if exc.errno not in (ssl.SSL_ERROR_WANT_READ,
                                 ssl.SSL_ERROR_WANT_WRITE,
                                 ssl.SSL_ERROR_SYSCALL):
                raise
        self._app_protocol.data_received(b''.join(data))
